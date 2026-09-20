# Case Study — Lost Device Investigation

> **Author:** Marcus Paula | Independent security engineering lab  
> **Date:** 2026-02  
> **Classification:** Fictional practice scenario — not a record of a real incident  
> **Environment:** a fictional enterprise multi-site lab environment (Site A)

---

## Background

This case study documents the investigation workflow for a lost corporate device scenario in a multi-site multi-site lab enterprise environment. Details have been anonymised. The methodology applies to macOS (MDM platform-managed) and Windows (AD/endpoint protection platform-managed) endpoints.

---

## Scenario

A member of staff reported a MacBook Pro missing after travel. The device had not returned to the office and the employee was uncertain whether it had been lost or stolen in transit.

**Device details (anonymised):**
- OS: macOS 14 (Sonoma)
- MDM: MDM platform (enrolled, managed)
- Endpoint protection: endpoint protection platform (endpoint protection platform)
- Storage: 1TB SSD (FileVault enabled)
- Last known location: Airport

---

## Investigation Timeline

### Hour 0 — Initial Report

1. Employee contacted IT via collaboration platform with incident details
2. IT escalated to DFIR lead (Marcus Paula)
3. Chain of custody form initiated
4. Case ID assigned: `IR-2024-EME-XXXX`

### Hour 0–1 — Immediate Actions

**MDM triage via MDM platform:**

```
MDM platform Actions performed:
1. Device → Management → Check-in forced
   Result: Device offline (no MDM contact since departure)

2. Device → Inventory → Last check-in timestamp pulled
   Result: Last seen 14:37 UTC (airport WiFi — 48 hours prior)

3. Device → Location (if enabled)
   Result: Location services — last GPS coordinates pulled

4. Device → Management → Enable Lost Mode
   Result: Command queued — will execute on next network contact

5. Device → Management → Lock device
   Result: Command queued with 6-digit PIN
```

**Active Directory — immediate account action:**

```powershell
# Check last logon across domain controllers
Get-ADUser -Identity "username" -Properties LastLogonDate, PasswordLastSet |
    Select-Object Name, LastLogonDate, PasswordLastSet

# Query last logon from all DCs (replicated attribute inconsistency)
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Get-ADUser -Identity "username" -Properties LastLogon -Server $DC.Name |
        Select-Object @{N="DC";E={$DC.Name}}, @{N="LastLogon";E={[DateTime]::FromFileTime($_.LastLogon)}}
}
```

**Password reset — performed immediately:**
- User password reset via AD
- User instructed NOT to use until investigation confirmed safe
- MFA tokens reviewed — no anomalous authentications detected

### Hour 1–4 — Evidence Collection

**MDM platform inventory pull:**
```
Collected via MDM platform:
- Hardware inventory (serial, disk encryption status)
- Installed software list
- Certificate list
- FileVault status: ENABLED (confirmed encrypted)
- Last user: [username]
- MDM platform MDM profile: intact
```

**FileVault status — critical finding:**

FileVault was confirmed enabled. This meant that without the recovery key or user credentials, disk data was protected. Even if device was in adversary hands, data was unreadable.

**endpoint protection platform (endpoint protection platform) review:**
```
endpoint protection platform telemetry pulled:
- Last AV scan: 24 hours prior
- No detections in last 30 days
- No suspicious network activity logged
- Agent: connected via corporate tunnel until last check-in
```

**Corporate VPN / Proxy logs:**

```bash
# Pulled from network team (anonymised)
# Reviewed: last 7 days of VPN authentication logs for the device
# Finding: Last connection was at airport — user initiated session
# No subsequent VPN connections detected
```

### Hour 4–24 — Extended Investigation

**Email and application access review:**
- Microsoft 365 audit log reviewed for account activity
- No logins from new/unknown IPs since device went offline
- No data exfiltration indicators in DLP logs
- collaboration platform session active — last activity matched device last-seen time

**MDM platform Lost Mode activation confirmed:**

```
# 16 hours after command queued, device came online briefly
# (airport WiFi, transit — device powering on)
# Lost Mode activated successfully
# PIN lock applied
# Custom message displayed: "Property of [Company]. Call: [IT number]"
# Location recorded: [international transit hub]
```

---

## Timeline Summary

| Time | Action | Actor |
|------|--------|-------|
| T+0h | Device reported missing | Employee |
| T+0.5h | IR case opened, MDM queried | DFIR Lead |
| T+1h | Lost Mode + Lock commands queued | DFIR Lead |
| T+1h | AD password reset | DFIR Lead |
| T+1h | endpoint protection platform and DLP telemetry reviewed | DFIR Lead |
| T+4h | No evidence of data breach confirmed | DFIR Lead |
| T+16h | Lost Mode activated on device | MDM platform MDM |
| T+48h | Device reported found — airport lost property | Employee |
| T+72h | Device returned, forensic image taken | DFIR Lead |
| T+96h | Device wiped and re-imaged | IT Team |

---

## Forensic Examination — On Device Return

When the device was returned via lost property:

```bash
# Pre-boot — do NOT power on immediately
# 1. Photograph device condition
# 2. Note any physical changes / damage
# 3. Place in Faraday bag until ready for examination

# On examination system:
# 4. Boot to external drive (Target Disk Mode or external boot)
# 5. Take forensic image of disk before any MDM platform re-enrolment
#    sudo diskutil list
#    sudo dd if=/dev/diskX of=/evidence/device-SERIAL-disk-image.dmg bs=4m

# 6. Hash the image
#    sha256sum /evidence/device-SERIAL-disk-image.dmg

# 7. Mount read-only for analysis
#    hdiutil attach -readonly /evidence/device-SERIAL-disk-image.dmg
```

**Findings from forensic image:**
- FileVault was intact — confirmed no decryption without credentials
- No new user accounts created
- No evidence of external boot attempts
- No evidence of disk cloning tools installed
- Lost property tag / form found in MDM platform device notes — legitimate recovery

---

## Scenario Outcome — Illustrative

- **Data breach:** Not confirmed — FileVault protected at rest
- **Account compromise:** Not detected — no anomalous auth events
- **Device:** Recovered, forensically examined, wiped and re-imaged
- **Classification:** Lost device — not theft

---

## Lessons Learned

| Finding | Recommendation |
|---------|---------------|
| MDM platform Lost Mode took 16h to activate (device offline) | Brief all staff: power off suspected stolen device to prevent adversary disabling MDM |
| No automated alert on MDM contact loss | Configure MDM platform alert: device not checked in > 24h |
| VPN logs not immediately accessible | Improve IR runbook: document log access paths for network team |
| No MDM-based geofencing | Evaluate MDM platform geofencing alerts for high-risk travel periods |

---

## Proposed Controls — Not Independently Validated

- FileVault full-disk encryption effective
- MDM platform MDM Lost Mode functional
- Active Directory rapid credential revocation worked
- endpoint protection platform telemetry available and useful for exclusion
- DLP monitoring provided exfiltration exclusion evidence

---

*Marcus Paula | Independent security engineering lab | Site A*
