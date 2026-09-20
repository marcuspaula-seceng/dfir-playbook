# Incident Report Template

> **Author:** Marcus Paula | Independent security engineering lab  
> **Version:** 1.0  
> **Classification:** Internal — DFIR Template

---

## Usage Instructions

Complete all sections. Sections marked **[REQUIRED]** must be filled in before closing the incident.
Use UTC for all timestamps. Facts only — no speculation in formal sections.

---

## Cover Page

| Field | Value |
|-------|-------|
| Report Title | Security Incident Report — [Brief Description] |
| Report Version | 1.0 |
| Case ID | IR-[YYYY]-[REGION]-[NNNN] |
| Classification | Internal / Confidential / Restricted |
| Report Date | |
| Lead Investigator | |
| Report Status | DRAFT / FINAL |

---

## Section 1 — Executive Summary [REQUIRED]

*2-5 sentences. Non-technical. Audience: management, legal, HR.*

```
[Write 2-5 sentences summarising:
- What happened
- What was affected
- What was done to contain it
- Current status]
```

**Severity:** P1 Critical / P2 High / P3 Medium / P4 Low

**Status:** Active / Contained / Eradicated / Closed

---

## Section 2 — Incident Details [REQUIRED]

| Field | Value |
|-------|-------|
| Incident type | e.g. Credential Compromise / Malware / Data Breach / Lost Device |
| Detection date/time (UTC) | |
| Incident start (estimated, UTC) | |
| Incident end (UTC) | |
| Detection source | e.g. Grafana Alert / endpoint protection platform / User Report / External notification |
| Affected systems | |
| Affected users | |
| Data affected | |
| Systems isolated? | Yes / No / Partial |

---

## Section 3 — Timeline [REQUIRED]

*All times in UTC. Be precise.*

| Date/Time (UTC) | Event | Actor |
|-----------------|-------|-------|
| | Incident start (estimated) | Attacker |
| | Initial detection | [Source] |
| | IR team notified | [Name] |
| | Containment action 1 | [Investigator] |
| | Scope determination | [Investigator] |
| | Eradication action 1 | [Investigator] |
| | Recovery initiated | [Investigator] |
| | Normal operations restored | [Investigator] |
| | Incident closed | [Investigator] |

---

## Section 4 — Technical Analysis [REQUIRED]

### 4.1 Attack Vector / Initial Access

```
[How did the attacker gain initial access?]
- Phishing
- Credential stuffing / breach data
- Exploited vulnerability (CVE-XXXX-XXXX)
- Insider
- Physical access
- Unknown — investigation ongoing
```

### 4.2 Techniques Observed (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Initial Access | | | |
| Persistence | | | |
| Privilege Escalation | | | |
| Defence Evasion | | | |
| Credential Access | | | |
| Discovery | | | |
| Lateral Movement | | | |
| Collection | | | |
| Exfiltration | | | |
| Command & Control | | | |

Reference: https://attack.mitre.org

### 4.3 Indicators of Compromise (IoCs)

**File IoCs:**
| Type | Value | Notes |
|------|-------|-------|
| MD5 | | |
| SHA256 | | |
| Filename | | |

**Network IoCs:**
| Type | Value | Notes |
|------|-------|-------|
| IP | | |
| Domain | | |
| URL | | |

**Host IoCs:**
| Type | Value | Notes |
|------|-------|-------|
| Registry key | | |
| File path | | |
| Mutex | | |
| Service name | | |

### 4.4 Evidence Collected

| Item | Type | Location | Hash (SHA256) |
|------|------|----------|---------------|
| | | | |
| | | | |

---

## Section 5 — Impact Assessment [REQUIRED]

### 5.1 Data Impact

| Data Type | Accessed? | Exfiltrated? | Volume | Sensitivity |
|-----------|-----------|-------------|--------|-------------|
| | | | | |
| | | | | |

### 5.2 System Impact

| System | Impact | Downtime | Business Impact |
|--------|--------|---------|----------------|
| | | | |

### 5.3 Regulatory / Legal Considerations

- [ ] Personal data (PII) involved — GDPR assessment required
- [ ] Payment card data — PCI DSS notification required
- [ ] Healthcare data — applicable regulation review
- [ ] Law enforcement referral — considered / in progress / not applicable
- [ ] Regulatory body notification — required / not required

---

## Section 6 — Containment & Eradication Actions

| # | Action | Performed by | Date/Time (UTC) | Result |
|---|--------|-------------|-----------------|--------|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

---

## Section 7 — Root Cause

**Root Cause:** [Single clear statement]

**Contributing Factors:**
1. [Factor 1]
2. [Factor 2]

---

## Section 8 — Lessons Learned [REQUIRED]

### 8.1 What Worked Well

1.
2.
3.

### 8.2 What Did Not Work / Gaps Identified

1.
2.
3.

### 8.3 Recommendations & Action Items

| # | Recommendation | Owner | Priority | Due Date | Status |
|---|---------------|-------|----------|---------|--------|
| 1 | | | P1/P2/P3 | | Open |
| 2 | | | | | |
| 3 | | | | | |

---

## Section 9 — Sign-off [REQUIRED]

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Lead Investigator | | | |
| IT Manager | | | |
| Security Lead | | | |
| Legal (if applicable) | | | |

---

## Appendices

### Appendix A — Raw Evidence Index

See Chain of Custody forms for all evidence items collected.

### Appendix B — Network Diagrams

[Attach if relevant to scope of incident]

### Appendix C — Supporting Screenshots / Logs

[Reference attached files]

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | | | Initial draft |
| | | | |

---

*Template — Marcus Paula | Independent security engineering lab | Site A*
