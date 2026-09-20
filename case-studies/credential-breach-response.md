# Case Study — Credential Breach Response

> **Author:** Marcus Paula | Independent security engineering lab  
> **Date:** 2026-02  
> **Classification:** Fictional practice scenario — not a record of a real incident  
> **Environment:** a fictional enterprise multi-site lab environment (Site A/Site B/Site C)

---

## Background

This case study documents an incident response to a suspected credential compromise involving a corporate account. The scenario illustrates the full response lifecycle from initial alert through to eradication and lessons learned.

Details are anonymised. The methodology is applicable across enterprise environments using Active Directory, SSO, and cloud platforms.

---

## Scenario

A Grafana alert triggered on an anomalous authentication pattern: a corporate user account successfully authenticated from two geographically separated locations within a 20-minute window — physically impossible travel.

**Impossible travel details:**
- Location A: Site A, Ireland (corporate IP — normal)
- Location B: Eastern Europe (residential ISP)
- Time gap: 18 minutes
- Authentication method: SSO (corporate IdP)

---

## Detection

### Alert Source

Grafana dashboard — "Impossible Travel Alert" rule:

```
Rule: concurrent_auth_different_geo
Condition:
  - Same user account
  - Two successful authentications
  - Geographic distance > 500km
  - Time delta < 60 minutes
Severity: P1 — Auto-page DFIR
```

### Initial Triage (first 15 minutes)

```powershell
# AD account status check
Get-ADUser -Identity "suspect.user" -Properties * |
    Select-Object Name, Enabled, LastLogonDate, PasswordLastSet,
    LockedOut, BadLogonCount, MemberOf

# Recent authentication events (all DCs)
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Get-WinEvent -ComputerName $DC.Name -FilterHashtable @{
        LogName = "Security"
        Id = 4624, 4625, 4648
        StartTime = (Get-Date).AddHours(-4)
    } -ErrorAction SilentlyContinue |
    Where-Object {$_.Message -match "suspect.user"} |
    Select-Object TimeCreated, Id, Message | Format-List
}
```

---

## Response Timeline

### T+0h — Alert Fired

- Grafana alert paged DFIR on-call
- DFIR lead (Marcus Paula) acknowledged within 5 minutes
- P1 incident declared

### T+0.25h — Immediate Containment

```powershell
# STEP 1: Disable account immediately (do not reset password yet)
Disable-ADAccount -Identity "suspect.user"
Write-Host "Account disabled: $(Get-Date -Format 'HH:mm:ss UTC')"

# STEP 2: Invalidate all active sessions (via IdP admin console)
# Performed via SSO provider admin panel — "Revoke all sessions"

# STEP 3: Confirm containment
Get-ADUser -Identity "suspect.user" -Properties Enabled | Select-Object Name, Enabled
```

**Confirmed:** Account disabled, all sessions terminated within 14 minutes of alert.

### T+0.5h — Stakeholder Notification

```
Notification sent via collaboration platform to:
- IT Manager
- Security Lead
- HR (account owner's manager)
- Legal (precautionary — potential data access)

Message: "Security incident in progress. Account [username] suspended 
pending investigation. Affected user has been notified and is cooperating."
```

### T+1h — Scope Determination

**What did the attacker authenticate to?**

Reviewed SSO audit logs for all applications accessed during the compromised window (18 minutes):

| Application | Access During Window | Data Accessible |
|-------------|---------------------|-----------------|
| Corporate email | Yes — 3 emails read | Internal communications |
| HR portal | No successful access | N/A |
| File storage | Yes — 2 files viewed | Project documents |
| Source control | No | N/A |
| Finance systems | No (MFA required separately) | N/A |

**Finding:** Attacker accessed email and file storage. No privileged systems accessed.

### T+2h — Attack Vector Investigation

**How were credentials obtained?**

```
Investigation path:
1. Phishing? → Check email security logs for recent suspicious emails
2. Password reuse? → Check breach notification services (HaveIBeenPwned API)
3. Keylogger/malware? → endpoint protection platform endpoint check on user's devices
4. Insider? → Interview user (cooperative)
```

**User interview notes:**

```
User reported:
- Received phishing email 3 days prior (reported to IT — ticket found)
- Clicked link "by accident" then immediately closed
- Did not enter credentials on the page (claims)
- Recently used corporate email on personal device (home PC — unmanaged)

Working hypothesis: credential from prior breach or home device compromise
```

**HaveIBeenPwned API check:**

```bash
# Check if email appears in known breach data
# (Using k-anonymity SHA1 prefix method)
EMAIL="<SYNTHETIC_USER>@example.invalid"
HASH=$(echo -n "$EMAIL" | sha1sum | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
PREFIX="${HASH:0:5}"
SUFFIX="${HASH:5}"

curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$EMAIL" \
  -H "hibp-api-key: $HIBP_KEY" | python3 -m json.tool
```

**Finding:** Account appeared in 2 third-party data breaches (unrelated to corporate systems).

**endpoint protection platform scan on corporate devices:**

```
Devices managed under this account:
- MacBook Pro (MDM platform managed): Full scan — No threats found
- Windows laptop (AD joined): Full scan — No threats found
- Personal devices: Outside corporate MDM scope
```

**Root cause:** Credential compromise via third-party breach, likely with password reused or similar to corporate password.

### T+4h — Eradication

```powershell
# 1. Reset password to complex random value
$NewPassword = [System.Web.Security.Membership]::GeneratePassword(20, 4)
$SecurePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
Set-ADAccountPassword -Identity "suspect.user" -NewPassword $SecurePassword -Reset

# 2. Force password change on next logon (additional safety)
Set-ADUser -Identity "suspect.user" -ChangePasswordAtLogon $true

# 3. Re-enable account
Enable-ADAccount -Identity "suspect.user"

# 4. Enforce MFA re-registration
# Performed via IdP admin: revoke MFA registrations → user must re-register
Write-Host "Eradication complete: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
```

### T+6h — Recovery & Monitoring

```
Recovery actions:
1. User account re-enabled with new password
2. User briefed: DO NOT reuse passwords, use password manager
3. User re-registered MFA (enforced via IdP)
4. Enhanced logging enabled on user account (30 days)
5. User added to "high-risk" watchlist in Grafana

Corporate controls reinforced:
- Remind all staff: do not reuse corporate passwords externally
- HIBP monitoring added for corporate email domain (bulk subscription)
- SSO policy reviewed: shorten session token lifetime
```

---

## Post-Incident Review

### What Worked Well

- Grafana impossible travel alert fired within 2 minutes of anomalous auth
- Account containment achieved in under 15 minutes
- SSO session revocation effective immediately
- endpoint protection platform clean scans ruled out device compromise quickly
- User cooperation throughout

### Gaps Identified

| Gap | Impact | Remediation |
|-----|--------|-------------|
| Password reuse — no controls | Attack vector | Enforce password manager; consider passkeys |
| Home device outside MDM scope | Unknown risk vector | Consider BYOD MDM or policy |
| Email accessed before containment | 3 emails exposed | Reduce alert-to-containment SLA target |
| No automatic account lockout on geo anomaly | 18-minute exposure window | Implement auto-lockout on impossible travel |
| MFA not required for all SSO apps | Some apps accessed without step-up | Enforce MFA for all SSO-connected apps |

### Illustrative Scenario Timings — Not Measured Results

| Metric | Value | Target |
|--------|-------|--------|
| Time to detect | 2 minutes | < 15 minutes |
| Time to contain (account disabled) | 14 minutes | < 30 minutes |
| Time to eradicate | 4 hours | < 8 hours |
| Time to recovery | 6 hours | < 12 hours |
| Total data exposure window | 18 minutes | Minimise |

---

## Proposed Controls Matrix — Scenario End State

| Control | Status Before | Status After |
|---------|--------------|-------------|
| Impossible travel alerting | Active | Active (threshold refined) |
| Auto-account lockout on anomaly | Absent | Planned (Q2) |
| Password reuse detection | Absent | HIBP monitoring added |
| MFA on all SSO apps | Partial | Enforced — all apps |
| Session token lifetime | 8 hours | Reduced to 2 hours |
| BYOD security policy | Absent | Policy drafted |

---

## Recommendations (Closed Loop)

1. **Implement auto-lockout on impossible travel** — remove human delay in containment
2. **Enforce unique passwords** — deploy enterprise password manager; Passkey migration roadmap
3. **HIBP corporate domain monitoring** — proactive breach notification
4. **Reduce SSO session lifetime** — balance security vs user experience (2h with silent re-auth)
5. **BYOD policy** — define acceptable use and minimum security controls for personal devices accessing corporate SSO

---

*Marcus Paula | Independent security engineering lab | Site A*
