# Incident Response — Full Lifecycle (PICERL)

> **Author:** Marcus Paula | Independent security engineering lab  
> **Last updated:** 2026-02-23  
> **Classification:** Internal — DFIR Reference  
> **Framework:** NIST SP 800-61r2 / SANS PICERL

---

## Overview

This runbook covers the complete Incident Response lifecycle as applied in enterprise multi-site lab environments. Adapted from NIST SP 800-61r2 and SANS methodology, refined through synthetic incident scenarios across a synthetic enterprise-scale population in Site A, Site B, and Site C.

---

## PICERL Framework

```
┌─────────────────────────────────────────────────────────────┐
│  P → Preparation                                            │
│  I → Identification                                         │
│  C → Containment                                            │
│  E → Eradication                                            │
│  R → Recovery                                               │
│  L → Lessons Learned                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1 — Preparation

### 1.1 IR Readiness (Standing Capabilities)

| Tool | Purpose | Environment |
|------|---------|-------------|
| MDM platform | macOS MDM — remote lock, wipe, log pull | a fictional enterprise multi-site lab environment |
| configuration-management platform | Linux configuration baseline | a fictional enterprise multi-site lab environment |
| endpoint protection platform (endpoint protection platform) | Endpoint Protection, AV, IPS | a fictional enterprise multi-site lab environment |
| Grafana | Real-time monitoring & alerting | a fictional enterprise multi-site lab environment |
| asset inventory | Device identity / Zero Trust | a fictional enterprise multi-site lab environment |
| Active Directory | IAM, GPO, account control | a fictional enterprise multi-site lab environment |
| collaboration platform | Internal comms + alerting | a fictional enterprise multi-site lab environment |

### 1.2 IR Team Roles

| Role | Responsibility |
|------|---------------|
| Incident Commander | Overall coordination, stakeholder comms |
| Lead Investigator | Technical forensics lead |
| Containment Lead | Network isolation, account lockdowns |
| Evidence Custodian | Chain of custody, evidence integrity |
| Communications Lead | Legal, HR, management notifications |

### 1.3 Pre-Incident Preparation

- [ ] IR contact list maintained and tested
- [ ] Evidence collection scripts pre-staged and signed
- [ ] Off-site evidence storage location confirmed
- [ ] Legal/HR notification templates ready
- [ ] MDM platform / endpoint protection platform / AD access confirmed for IR team
- [ ] Offline backup of critical system baselines

---

## Phase 2 — Identification

### 2.1 Alert Sources

```
SIEM alerts → Grafana dashboards → endpoint protection platform detections → User reports → MDM anomalies
```

### 2.2 Initial Triage Questions

1. What system(s) are affected?
2. What is the business criticality of the affected system(s)?
3. Is this a confirmed incident or a potential incident?
4. What is the estimated scope (single device / department / organisation)?
5. Is data exfiltration a concern?
6. Is the incident ongoing or contained?

### 2.3 Incident Classification

| Severity | Criteria | Response Time |
|----------|----------|--------------|
| P1 — Critical | Active breach, data exfiltration, ransomware | 15 minutes |
| P2 — High | Confirmed malware, account compromise, privilege escalation | 1 hour |
| P3 — Medium | Suspicious activity, policy violation, potential phishing | 4 hours |
| P4 — Low | Security alert requiring investigation, no confirmed impact | 24 hours |

### 2.4 Evidence of Compromise (IoC Collection)

```bash
# Initial IoC sweep
# - Collect IP addresses of suspect connections
# - Collect file hashes of suspect executables
# - Collect domain names from DNS cache
# - Collect account names involved
# - Record timestamps (all in UTC)
```

---

## Phase 3 — Containment

### 3.1 Short-Term Containment

**Do NOT reboot the system** unless absolutely necessary — volatile evidence will be lost.

```
Priority order:
1. Isolate affected system(s) at network level
2. Preserve volatile state (RAM, network connections, processes)
3. Revoke / lock compromised accounts in Active Directory
4. Block malicious IPs/domains at perimeter
5. Notify stakeholders
```

### 3.2 Network Isolation Options

| Method | Speed | Evidence Preservation | Notes |
|--------|-------|----------------------|-------|
| Physical disconnect | Immediate | High risk of evidence loss | Last resort |
| VLAN isolation | Fast | Good | Preferred for managed devices |
| Firewall ACL | Fast | Good | Use when physical access not immediate |
| MDM platform remote commands | Minutes | Good | macOS managed devices |
| AD account lockout | Minutes | No network effect | Credential compromise |

### 3.3 Account Containment (Active Directory)

```powershell
# Disable compromised account
Disable-ADAccount -Identity "username"

# Force password reset
Set-ADAccountPassword -Identity "username" -Reset -NewPassword (Read-Host -AsSecureString)

# Remove from elevated groups
Remove-ADGroupMember -Identity "Domain Admins" -Members "username"

# Check all group memberships
Get-ADPrincipalGroupMembership -Identity "username" | Select-Object Name
```

### 3.4 Long-Term Containment

- Deploy updated endpoint protection platform signatures
- Apply GPO restrictions to affected OU
- Enable enhanced logging (Sysmon, PowerShell transcription)
- Reset all service accounts that may have been exposed

---

## Phase 4 — Eradication

### 4.1 Root Cause Analysis

Before eradication, confirm:
- [ ] Root cause identified
- [ ] All affected systems identified
- [ ] All attacker persistence mechanisms identified
- [ ] All compromised credentials identified

### 4.2 Eradication Actions

```
1. Remove malicious files / artefacts
2. Delete attacker-created accounts
3. Remove unauthorised scheduled tasks / services / WMI subscriptions
4. Remove persistence from registry / cron / startup
5. Patch exploited vulnerability
6. Reset all compromised credentials
7. Rebuild affected systems if required (do not trust heavily compromised hosts)
```

### 4.3 Verify Eradication

```bash
# Linux — verify no remnants
find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null
crontab -l && for user in $(cut -d: -f1 /etc/passwd); do crontab -u $user -l 2>/dev/null; done
ss -antpe | grep ESTABLISHED

# Windows — verify no remnants
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath
Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select-Object Name, LastLogon
```

---

## Phase 5 — Recovery

### 5.1 Recovery Sequence

```
1. Restore from clean backup (verified integrity)
2. Apply all outstanding patches
3. Deploy hardened configuration (via configuration-management platform / GPO)
4. Re-enrol in MDM (MDM platform) if required
5. Restore network access in stages (monitored)
6. Verify normal operations
7. Enhanced monitoring period (minimum 30 days)
```

### 5.2 Return to Production Criteria

- [ ] System rebuilt or verified clean
- [ ] All patches applied
- [ ] Credentials reset
- [ ] MDM / endpoint protection re-enrolled
- [ ] Enhanced logging confirmed active
- [ ] Security team sign-off

---

## Phase 6 — Lessons Learned

### 6.1 Post-Incident Review (PIR)

Conduct within **5 business days** of incident closure.

**PIR Agenda:**
1. Timeline walkthrough — what happened, when, how detected
2. Detection gap analysis — why was this not detected sooner?
3. Response effectiveness — what worked, what didn't
4. Containment speed — could we have acted faster?
5. Control gaps — what controls would have prevented/limited this?
6. Action items — specific, assigned, time-bound

### 6.2 Metrics to Record

| Metric | Target |
|--------|--------|
| Mean Time to Detect (MTTD) | < 24 hours |
| Mean Time to Respond (MTTR) | < 4 hours (P1) |
| Mean Time to Contain | < 2 hours (P1) |
| Evidence preservation rate | 100% |

### 6.3 Report

Complete incident report using: [resources/incident-report-template.md](../resources/incident-report-template.md)

---

## Communication Templates

### Initial Notification (P1/P2)

```
Subject: [SECURITY INCIDENT P1] - [Brief Description] - [Date]

Team,

A security incident has been identified affecting [system/scope].

Status: ACTIVE INVESTIGATION
Affected: [systems]
Severity: P1/P2
Incident Commander: [name]

Next update: [time]

Do NOT discuss details on unsecured channels.
```

### Stakeholder Update

```
Subject: [SECURITY INCIDENT] Update #[N] - [Date Time]

Incident: [ID]
Status: [Containment / Eradication / Recovery]

Summary: [2-3 sentences — factual, no speculation]

Actions taken:
- [Action 1]
- [Action 2]

Next steps:
- [Step 1]

Next update: [time]
```

---

*Marcus Paula | Independent security engineering lab | Site A*
