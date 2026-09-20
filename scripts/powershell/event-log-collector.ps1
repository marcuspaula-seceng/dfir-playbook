#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Event Log Collector — DFIR Evidence Exporter

.DESCRIPTION
    Exports Windows Event Logs with filtering options for DFIR investigations.
    Supports export to EVTX, CSV, and JSON formats.
    Part of the DFIR Playbook — github.com/marcuspaula-seceng

.AUTHOR
    Marcus Paula | Independent security engineering lab

.VERSION
    1.0.0

.DATE
    2026-02-23

.USAGE
    powershell -ExecutionPolicy Bypass -File event-log-collector.ps1
    powershell -ExecutionPolicy Bypass -File event-log-collector.ps1 -HoursBack 48 -OutputDir "D:\evidence\logs"
    powershell -ExecutionPolicy Bypass -File event-log-collector.ps1 -EventIds 4624,4625,4648
#>

[CmdletBinding()]
param(
    [string]$OutputDir      = "C:\DFIR-Evidence\EventLogs",
    [int]$HoursBack         = 72,
    [int[]]$EventIds        = @(),
    [string]$Format         = "EVTX",   # EVTX | CSV | JSON | ALL
    [switch]$SecurityOnly   = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

function Write-Log {
    param([string]$Msg, [string]$Level="INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $col = switch($Level){ "WARN"{"Yellow"} "ERR"{"Red"} default{"Cyan"} }
    Write-Host "[$ts] $Msg" -ForegroundColor $col
}

Write-Log "Event Log Collector — Marcus Paula | Independent security engineering lab"
Write-Log "Output: $OutputDir"
Write-Log "Hours back: $HoursBack"

$StartTime = (Get-Date).AddHours(-$HoursBack)

# ---------------------------------------------------------------------------
# Define log channels to collect
# ---------------------------------------------------------------------------
$LogChannels = if ($SecurityOnly) {
    @("Security")
} else {
    @(
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "Microsoft-Windows-WinRM/Operational",
        "Microsoft-Windows-Sysmon/Operational"
    )
}

# ---------------------------------------------------------------------------
# Key DFIR Event IDs with descriptions
# ---------------------------------------------------------------------------
$KeyEventIDs = @{
    # Authentication
    4624 = "Successful logon"
    4625 = "Failed logon"
    4634 = "Logoff"
    4647 = "User-initiated logoff"
    4648 = "Logon with explicit credentials"
    4672 = "Special privileges assigned to new logon"
    4768 = "Kerberos TGT requested"
    4769 = "Kerberos service ticket requested"
    4776 = "NTLM authentication"

    # Account Management
    4720 = "User account created"
    4722 = "User account enabled"
    4723 = "Password change attempted"
    4724 = "Password reset attempted"
    4725 = "User account disabled"
    4726 = "User account deleted"
    4728 = "User added to security-enabled global group"
    4732 = "User added to security-enabled local group"
    4756 = "User added to security-enabled universal group"

    # Policy & System
    4719 = "System audit policy changed"
    4946 = "Firewall rule added"
    4950 = "Firewall setting changed"
    1102 = "Audit log cleared"
    104  = "System log cleared"

    # Process & Execution
    4688 = "New process created"
    4689 = "Process terminated"
    7045 = "New service installed"
    7036 = "Service state changed"

    # Scheduled Tasks
    4698 = "Scheduled task created"
    4699 = "Scheduled task deleted"
    4700 = "Scheduled task enabled"
    4702 = "Scheduled task updated"

    # Object Access
    4663 = "Object access attempted"
    4670 = "Object permissions changed"
    4907 = "Object audit settings changed"

    # PowerShell
    4103 = "PowerShell module logging"
    4104 = "PowerShell script block logging"
}

# ---------------------------------------------------------------------------
# Export individual log channel
# ---------------------------------------------------------------------------
function Export-LogChannel {
    param(
        [string]$Channel,
        [string]$OutDir,
        [datetime]$Since,
        [int[]]$FilterIDs
    )

    $safeName = $Channel -replace "/","_" -replace "\\","_" -replace ":","_"

    # Check if log exists
    $logExists = Get-WinEvent -ListLog $Channel -ErrorAction SilentlyContinue
    if (-not $logExists) {
        Write-Log "Log not available: $Channel" -Level "WARN"
        return
    }

    # Always export raw EVTX
    $evtxPath = "$OutDir\$safeName.evtx"
    wevtutil epl $Channel $evtxPath 2>$null
    Write-Log "EVTX exported: $Channel -> $safeName.evtx"

    # Filtered events (CSV/JSON)
    try {
        $filterHash = @{
            LogName   = $Channel
            StartTime = $Since
        }
        if ($FilterIDs.Count -gt 0) {
            $filterHash.Id = $FilterIDs
        }

        $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue
        if (-not $events) { return }

        $parsed = $events | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated  = $_.TimeCreated
                Id           = $_.Id
                Description  = if ($KeyEventIDs.ContainsKey($_.Id)) { $KeyEventIDs[$_.Id] } else { "" }
                Level        = $_.LevelDisplayName
                Source       = $_.ProviderName
                Computer     = $_.MachineName
                Message      = $_.Message -replace "`r`n"," " -replace "`n"," "
            }
        }

        # CSV
        $parsed | Export-Csv -Path "$OutDir\$safeName-filtered.csv" -NoTypeInformation -Encoding UTF8
        Write-Log "CSV exported: $safeName-filtered.csv ($($parsed.Count) events)"

        # JSON
        $parsed | ConvertTo-Json -Depth 3 | Out-File "$OutDir\$safeName-filtered.json" -Encoding UTF8

    } catch {
        Write-Log "Could not filter events for $Channel : $_" -Level "WARN"
    }
}

# ---------------------------------------------------------------------------
# Security-focused extraction
# ---------------------------------------------------------------------------
function Export-SecuritySummary {
    Write-Log "Generating security summary..."

    $outFile = "$OutputDir\SECURITY-SUMMARY-$Timestamp.txt"

    @"
============================
 SECURITY EVENT SUMMARY
============================
Author     : Marcus Paula | Independent security engineering lab
Host       : $env:COMPUTERNAME
Generated  : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
Period     : Last $HoursBack hours (since $StartTime)
============================

"@ | Out-File $outFile -Encoding UTF8

    $summaryEvents = @(
        @{Ids=@(4625); Label="Failed Logons"; Max=50},
        @{Ids=@(4624); Label="Successful Logons"; Max=50},
        @{Ids=@(4648); Label="Explicit Credential Logons"; Max=20},
        @{Ids=@(4720,4722,4724,4725,4726,4728,4732); Label="Account Management Events"; Max=30},
        @{Ids=@(4698,4699,4700,4702); Label="Scheduled Task Changes"; Max=20},
        @{Ids=@(7045); Label="New Services Installed"; Max=20},
        @{Ids=@(1102,104); Label="Log Cleared Events"; Max=10},
        @{Ids=@(4104); Label="PowerShell Script Block Log"; Max=20}
    )

    foreach ($item in $summaryEvents) {
        "`n=== $($item.Label) ===" | Out-File $outFile -Append -Encoding UTF8
        try {
            $evts = Get-WinEvent -FilterHashtable @{
                LogName   = "Security","System","Microsoft-Windows-PowerShell/Operational"
                StartTime = $StartTime
                Id        = $item.Ids
            } -MaxEvents $item.Max -ErrorAction SilentlyContinue

            if ($evts) {
                $evts | Select-Object TimeCreated, Id, Message |
                    Format-List | Out-File $outFile -Append -Encoding UTF8
                "$($evts.Count) events found." | Out-File $outFile -Append -Encoding UTF8
            } else {
                "No events found." | Out-File $outFile -Append -Encoding UTF8
            }
        } catch {
            "Error collecting: $_" | Out-File $outFile -Append -Encoding UTF8
        }
    }

    Write-Log "Security summary: $outFile"
}

# ---------------------------------------------------------------------------
# Hash all outputs
# ---------------------------------------------------------------------------
function Set-EvidenceHashes {
    Write-Log "Hashing all output files..."
    Get-ChildItem $OutputDir -File -Recurse | ForEach-Object {
        $hash = Get-FileHash $_.FullName -Algorithm SHA256
        "$($hash.Hash)  $($_.FullName)"
    } | Out-File "$OutputDir\SHA256SUMS-$Timestamp.txt" -Encoding UTF8
    Write-Log "Hashes saved: SHA256SUMS-$Timestamp.txt"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Log "Collecting from $($LogChannels.Count) log channels..."

foreach ($channel in $LogChannels) {
    Export-LogChannel -Channel $channel -OutDir $OutputDir -Since $StartTime -FilterIDs $EventIds
}

Export-SecuritySummary
Set-EvidenceHashes

$total = (Get-ChildItem $OutputDir -File -Recurse).Count
Write-Log "=== COMPLETE === $total files in $OutputDir"
