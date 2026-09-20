# Live Triage — Windows

> **Author:** Marcus Paula | Independent security engineering lab  
> **Last updated:** 2026-02-23  
> **Classification:** Internal — DFIR Reference  
> **Applies to:** Windows 10/11, Windows Server 2019/2022 (managed and unmanaged)

---

## Pre-Triage Checklist

- [ ] Written authorisation received
- [ ] Chain of custody form initiated
- [ ] Evidence drive connected (dedicated path, not `C:\`)
- [ ] Time synchronised (`w32tm /query /status`)
- [ ] MDM platform / AD / endpoint protection platform telemetry pulled for context
- [ ] Triage scripts signed or ExecutionPolicy set appropriately
- [ ] Do NOT reboot, hibernate, or sleep the system

---

## Phase 1 — Volatile Data

### 1.1 System Identification

```powershell
# System identity and time (UTC)
Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC" | Out-File evidence\timestamp.txt
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber, OsArchitecture | Format-List
hostname
[System.TimeZoneInfo]::Local
```

### 1.2 Network State

```powershell
# Active network connections (most critical — do this first)
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
  Sort-Object RemoteAddress | Format-Table -AutoSize

# All connections including listening
netstat -anob | Out-File evidence\netstat.txt

# ARP cache
Get-NetNeighbor | Out-File evidence\arp.txt

# DNS cache (can reveal C2 domains)
Get-DnsClientCache | Out-File evidence\dns_cache.txt

# Active network adapters
Get-NetAdapter | Get-NetIPAddress | Format-Table -AutoSize

# Firewall rules (enabled, non-default)
Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True" -and $_.DisplayGroup -notmatch "^@"} |
  Select-Object DisplayName, Direction, Action, Profile | Format-Table -AutoSize
```

### 1.3 Running Processes

```powershell
# Full process list with parent and path
Get-Process | Select-Object Id, Name, Path, Company, CPU, WorkingSet, StartTime |
  Sort-Object StartTime -Descending | Format-Table -AutoSize

# Processes with network connections (correlate with netstat)
Get-NetTCPConnection -State Established |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      PID = $_.OwningProcess
      Process = $proc.Name
      Path = $proc.Path
      LocalPort = $_.LocalPort
      RemoteAddress = $_.RemoteAddress
      RemotePort = $_.RemotePort
    }
  } | Format-Table -AutoSize

# Services and associated executables
Get-WmiObject Win32_Service |
  Select-Object Name, State, StartMode, PathName |
  Where-Object {$_.State -eq "Running"} | Format-Table -AutoSize
```

### 1.4 Logged-in Users & Sessions

```powershell
# Current interactive sessions
query session
query user

# Recent logons (Security event log)
Get-WinEvent -LogName Security -FilterHashtable @{Id=4624} -MaxEvents 50 |
  Select-Object TimeCreated, Message | Format-List

# Failed logons
Get-WinEvent -LogName Security -FilterHashtable @{Id=4625} -MaxEvents 50 |
  Select-Object TimeCreated, Message | Format-List
```

---

## Phase 2 — Persistence Mechanisms

### 2.1 Autorun Locations

```powershell
# Registry run keys (most common persistence)
$runKeys = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $runKeys) {
  Write-Host "`n=== $key ===" -ForegroundColor Cyan
  Get-ItemProperty $key -ErrorAction SilentlyContinue
}

# Scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} |
  Select-Object TaskName, TaskPath, State |
  Sort-Object TaskPath | Format-Table -AutoSize

# Scheduled task actions (show what each task runs)
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} |
  ForEach-Object {
    $task = $_
    $task.Actions | ForEach-Object {
      [PSCustomObject]@{
        Task = $task.TaskName
        Execute = $_.Execute
        Arguments = $_.Arguments
      }
    }
  } | Format-Table -AutoSize
```

### 2.2 Services

```powershell
# Non-Microsoft services
Get-WmiObject Win32_Service |
  Where-Object {$_.PathName -notmatch "Windows|Microsoft"} |
  Select-Object Name, StartMode, State, PathName | Format-Table -AutoSize

# Services pointing to temp paths (red flag)
Get-WmiObject Win32_Service |
  Where-Object {$_.PathName -match "Temp|AppData|Public|Downloads"} |
  Select-Object Name, State, PathName | Format-Table -AutoSize
```

### 2.3 WMI Persistence

```powershell
# WMI event subscriptions (common advanced persistence)
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### 2.4 Local Users & Groups

```powershell
# Local administrators
net localgroup administrators

# All local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Format-Table

# Domain admins (if domain-joined)
net group "Domain Admins" /domain 2>$null
```

---

## Phase 3 — Filesystem Artefacts

### 3.1 Recently Modified Files

```powershell
# Files modified in last 24 hours in suspicious locations
$suspiciousPaths = @("$env:TEMP", "$env:APPDATA", "C:\Users\Public", "$env:USERPROFILE\Downloads")
foreach ($path in $suspiciousPaths) {
  Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
    Select-Object FullName, LastWriteTime, Length | Format-Table
}
```

### 3.2 PowerShell History

```powershell
# PowerShell command history (all users)
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" |
  ForEach-Object { Write-Host "`n=== $($_.FullName) ==="; Get-Content $_ }

# Transcript logs
Get-ChildItem "C:\Users\*\Documents\*transcript*" -Recurse -ErrorAction SilentlyContinue
```

### 3.3 Prefetch Files

```powershell
# Prefetch (execution evidence — requires admin)
Get-ChildItem C:\Windows\Prefetch -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, LastWriteTime | Select-Object -First 50
```

---

## Phase 4 — Event Log Collection

```powershell
# Export key event logs
$logs = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational",
          "Microsoft-Windows-Sysmon/Operational")
foreach ($log in $logs) {
  $safe = $log -replace "/", "_" -replace "\\", "_"
  wevtutil epl $log "evidence\$safe.evtx" 2>$null
  Write-Host "Exported: $log"
}
```

---

## Phase 5 — Evidence Preservation

```powershell
# Hash all evidence files
Get-ChildItem evidence\ | ForEach-Object {
  $hash = Get-FileHash $_.FullName -Algorithm SHA256
  "$($hash.Hash)  $($_.Name)"
} | Out-File evidence\SHA256SUMS.txt

Write-Host "Evidence hashed. Chain of custody preserved."
```

---

## Windows DFIR — Red Flags

| Category | Red Flag |
|----------|----------|
| Processes | `powershell.exe` with no window; process from `%TEMP%` |
| Network | Connections to unusual foreign IPs; DNS queries for DGA domains |
| Registry | Run key pointing to `%APPDATA%` or `%TEMP%` |
| Services | Service with random name; service path in user profile |
| WMI | Any WMI event subscription (unusual in most environments) |
| Scheduled Tasks | Task with base64-encoded PowerShell |
| Accounts | New local admin account; account not in AD |
| Logs | Security log cleared (Event ID 1102); Sysmon disabled |

---

## Key Event IDs — Windows Security

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned |
| 4698 | Scheduled task created |
| 4720 | User account created |
| 4732 | User added to local admin group |
| 1102 | Audit log cleared |
| 7045 | New service installed |
| 4688 | New process created (if auditing enabled) |

---

## Automated Script

See: [scripts/powershell/windows-triage.ps1](../scripts/powershell/windows-triage.ps1)

---

*Marcus Paula | Independent security engineering lab | Site A*
