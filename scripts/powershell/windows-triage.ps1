#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Live Triage Script — Automated Evidence Collection

.DESCRIPTION
    Collects volatile evidence from a live Windows system for DFIR purposes.
    Part of the DFIR Playbook — github.com/marcuspaula-seceng

.AUTHOR
    Marcus Paula | Independent security engineering lab

.VERSION
    1.0.0

.DATE
    2026-02-23

.USAGE
    # Run as Administrator:
    powershell -ExecutionPolicy Bypass -File windows-triage.ps1
    powershell -ExecutionPolicy Bypass -File windows-triage.ps1 -EvidenceRoot "D:\evidence"
#>

[CmdletBinding()]
param(
    [string]$EvidenceRoot = "C:\DFIR-Evidence",
    [string]$CaseID = "UNSET"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
$Timestamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$Hostname    = $env:COMPUTERNAME
$EvidenceDir = Join-Path $EvidenceRoot "$Hostname-$Timestamp"
$Investigator = "Marcus Paula | Independent security engineering lab"

$Dirs = @("network","processes","users","persistence","filesystem","logs","registry")
foreach ($d in $Dirs) { New-Item -ItemType Directory -Path "$EvidenceDir\$d" -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $colour = switch ($Level) { "WARN" {"Yellow"} "ERR" {"Red"} default {"Green"} }
    Write-Host "[$ts] [$Level] $Msg" -ForegroundColor $colour
    "[$ts] [$Level] $Msg" | Out-File "$EvidenceDir\triage.log" -Append
}

function Save-Output {
    param([string]$File, [scriptblock]$Script)
    try {
        $output = & $Script
        $output | Out-File -FilePath $File -Encoding UTF8
    } catch {
        "ERROR: $_" | Out-File -FilePath $File -Encoding UTF8
    }
}

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------
Write-Log "Starting Windows Live Triage"
$meta = @"
==============================
 WINDOWS TRIAGE - START
==============================
Investigator : $Investigator
Script ver.  : 1.0.0
Case ID      : $CaseID
Hostname     : $Hostname
Start time   : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") UTC
OS           : $((Get-WmiObject Win32_OperatingSystem).Caption)
OS Build     : $((Get-WmiObject Win32_OperatingSystem).BuildNumber)
Architecture : $env:PROCESSOR_ARCHITECTURE
Domain       : $env:USERDOMAIN
==============================
"@
$meta | Out-File "$EvidenceDir\triage-metadata.txt"
Write-Host $meta

# ---------------------------------------------------------------------------
# Network — Volatile (collect first)
# ---------------------------------------------------------------------------
Write-Log "Collecting network state..."

Save-Output "$EvidenceDir\network\tcp-connections.txt" {
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        Sort-Object State, RemoteAddress | Format-Table -AutoSize
}

Save-Output "$EvidenceDir\network\tcp-connections-with-process.txt" {
    Get-NetTCPConnection | ForEach-Object {
        $conn = $_
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress  = $conn.LocalAddress
            LocalPort     = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort    = $conn.RemotePort
            State         = $conn.State
            PID           = $conn.OwningProcess
            ProcessName   = if ($proc) { $proc.Name } else { "N/A" }
            ProcessPath   = if ($proc) { $proc.Path } else { "N/A" }
        }
    } | Format-Table -AutoSize
}

Save-Output "$EvidenceDir\network\netstat-raw.txt" { netstat -anob }
Save-Output "$EvidenceDir\network\arp-cache.txt" { Get-NetNeighbor | Format-Table -AutoSize }
Save-Output "$EvidenceDir\network\dns-cache.txt" { Get-DnsClientCache | Format-Table -AutoSize }
Save-Output "$EvidenceDir\network\interfaces.txt" { Get-NetIPAddress | Format-Table -AutoSize }
Save-Output "$EvidenceDir\network\routes.txt" { Get-NetRoute | Format-Table -AutoSize }
Save-Output "$EvidenceDir\network\hosts-file.txt" { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }

Write-Log "Network collection done."

# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------
Write-Log "Collecting process information..."

Save-Output "$EvidenceDir\processes\process-list.txt" {
    Get-Process | Select-Object Id, Name, Path, Company, CPU, WorkingSet,
        @{N="StartTime";E={if($_.StartTime){$_.StartTime}else{"N/A"}}} |
        Sort-Object StartTime -Descending | Format-Table -AutoSize
}

Save-Output "$EvidenceDir\processes\services-running.txt" {
    Get-WmiObject Win32_Service |
        Where-Object {$_.State -eq "Running"} |
        Select-Object Name, State, StartMode, PathName | Format-Table -AutoSize
}

Save-Output "$EvidenceDir\processes\services-all.txt" {
    Get-WmiObject Win32_Service |
        Select-Object Name, State, StartMode, PathName |
        Sort-Object Name | Format-Table -AutoSize
}

# Services in suspicious paths
Save-Output "$EvidenceDir\processes\services-suspicious-paths.txt" {
    Get-WmiObject Win32_Service |
        Where-Object {$_.PathName -match "Temp|AppData|Public|Downloads|\\Users\\"} |
        Select-Object Name, State, PathName | Format-Table -AutoSize
}

Write-Log "Process collection done."

# ---------------------------------------------------------------------------
# Users and Sessions
# ---------------------------------------------------------------------------
Write-Log "Collecting user and session data..."

Save-Output "$EvidenceDir\users\local-users.txt" {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
        PasswordExpires, Description | Format-Table -AutoSize
}

Save-Output "$EvidenceDir\users\local-admins.txt" { net localgroup administrators }
Save-Output "$EvidenceDir\users\sessions.txt" { query session }

Save-Output "$EvidenceDir\users\logon-events-success.txt" {
    Get-WinEvent -LogName Security -FilterHashtable @{Id=4624} -MaxEvents 100 |
        Select-Object TimeCreated, Id, Message | Format-List
}

Save-Output "$EvidenceDir\users\logon-events-failed.txt" {
    Get-WinEvent -LogName Security -FilterHashtable @{Id=4625} -MaxEvents 100 |
        Select-Object TimeCreated, Id, Message | Format-List
}

Write-Log "User collection done."

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
Write-Log "Collecting persistence mechanisms..."

# Registry run keys
$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

$runOutput = foreach ($key in $RunKeys) {
    "=== $key ==="
    Get-ItemProperty $key -ErrorAction SilentlyContinue
    ""
}
$runOutput | Out-File "$EvidenceDir\persistence\registry-run-keys.txt" -Encoding UTF8

# Scheduled tasks
Save-Output "$EvidenceDir\persistence\scheduled-tasks.txt" {
    Get-ScheduledTask |
        Where-Object {$_.State -ne "Disabled"} |
        Select-Object TaskName, TaskPath, State, Author |
        Sort-Object TaskPath | Format-Table -AutoSize
}

Save-Output "$EvidenceDir\persistence\scheduled-task-actions.txt" {
    Get-ScheduledTask |
        Where-Object {$_.State -ne "Disabled"} |
        ForEach-Object {
            $task = $_
            foreach ($action in $task.Actions) {
                [PSCustomObject]@{
                    Task      = $task.TaskName
                    TaskPath  = $task.TaskPath
                    Execute   = $action.Execute
                    Arguments = $action.Arguments
                }
            }
        } | Format-Table -AutoSize
}

# WMI subscriptions
Save-Output "$EvidenceDir\persistence\wmi-subscriptions.txt" {
    "=== EventFilter ===" | Out-File -Append
    Get-WMIObject -Namespace root\subscription -Class __EventFilter
    "=== EventConsumer ===" | Out-File -Append
    Get-WMIObject -Namespace root\subscription -Class __EventConsumer
    "=== FilterToConsumerBinding ===" | Out-File -Append
    Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
}

# Startup folders
Save-Output "$EvidenceDir\persistence\startup-folders.txt" {
    "=== All Users Startup ==="
    Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
    "=== Current User Startup ==="
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
}

Write-Log "Persistence collection done."

# ---------------------------------------------------------------------------
# Filesystem Artefacts
# ---------------------------------------------------------------------------
Write-Log "Collecting filesystem artefacts..."

# PowerShell history
Save-Output "$EvidenceDir\filesystem\powershell-history.txt" {
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" |
        ForEach-Object {
            "=== $($_.FullName) ==="
            Get-Content $_ -ErrorAction SilentlyContinue
            ""
        }
}

# Prefetch
Save-Output "$EvidenceDir\filesystem\prefetch.txt" {
    Get-ChildItem C:\Windows\Prefetch -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object Name, LastWriteTime, Length |
        Select-Object -First 100 | Format-Table -AutoSize
}

# Temp directories
Save-Output "$EvidenceDir\filesystem\temp-files.txt" {
    $temps = @($env:TEMP, "C:\Windows\Temp", "C:\Users\Public")
    foreach ($dir in $temps) {
        "=== $dir ==="
        Get-ChildItem $dir -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object FullName, LastWriteTime, Length |
            Select-Object -First 50 | Format-Table -AutoSize
    }
}

Write-Log "Filesystem collection done."

# ---------------------------------------------------------------------------
# Event Log Export
# ---------------------------------------------------------------------------
Write-Log "Exporting event logs..."

$LogsToExport = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational"
)

foreach ($log in $LogsToExport) {
    $safe   = $log -replace "/","_" -replace "\\","_"
    $outEvtx = "$EvidenceDir\logs\$safe.evtx"
    try {
        wevtutil epl $log $outEvtx 2>$null
        Write-Log "Exported: $log"
    } catch {
        Write-Log "Could not export: $log" -Level "WARN"
    }
}

# Sysmon if present
if (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue) {
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" "$EvidenceDir\logs\Sysmon.evtx" 2>$null
    Write-Log "Exported Sysmon log."
}

Write-Log "Event log export done."

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
Write-Log "Hashing evidence files..."

Get-ChildItem "$EvidenceDir" -Recurse -File | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    "$($hash.Hash)  $($_.FullName)"
} | Out-File "$EvidenceDir\SHA256SUMS.txt" -Encoding UTF8

# ---------------------------------------------------------------------------
# Complete
# ---------------------------------------------------------------------------
$end = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$fileCount = (Get-ChildItem "$EvidenceDir" -Recurse -File).Count

Write-Log "=== TRIAGE COMPLETE ==="
Write-Log "End time  : $end UTC"
Write-Log "Files     : $fileCount"
Write-Log "Evidence  : $EvidenceDir"
Write-Log "Remember to complete chain of custody documentation."

Add-Content -Path "$EvidenceDir\triage-metadata.txt" -Value "`nEnd time: $end UTC`nFiles collected: $fileCount"
