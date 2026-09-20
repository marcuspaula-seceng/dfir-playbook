# DFIR Tools Reference — Windows

> **Author:** Marcus Paula | Independent security engineering lab  
> **Last updated:** 2026-02-23  
> **Classification:** Internal — DFIR Reference

---

## Essential Windows DFIR Toolkit

Download all tools to a dedicated forensic USB drive. Do not install on the target system.

| Tool | Purpose | Download |
|------|---------|----------|
| Sysinternals Suite | Live triage, process analysis | https://learn.microsoft.com/sysinternals |
| FTK Imager | Disk imaging, evidence acquisition | https://www.exterro.com/ftk-imager |
| Volatility 3 | Memory forensics | https://www.volatilityfoundation.org |
| WinPmem / DumpIt | Memory acquisition | https://github.com/Velocidex/WinPmem |
| Autopsy | Forensic case management (GUI) | https://www.autopsy.com |
| KAPE | Triage collection (artefacts) | https://www.kroll.com/kape |
| Eric Zimmermann Tools | Artefact parsing | https://ericzimmerman.github.io |
| Magnet AXIOM | Enterprise forensics | https://www.magnetforensics.com |
| Redline | Memory + IOC analysis | https://fireeye.market/apps/211364 |
| Wireshark | Network capture / analysis | https://www.wireshark.org |
| NetworkMiner | Network forensics (passive) | https://www.netresec.com |
| YARA | Malware detection rules | https://virustotal.github.io/yara |
| CyberChef | Data transformation | https://gchq.github.io/CyberChef |
| Detect-It-Easy | Packer / compiler detection | https://github.com/horsicq/Detect-It-Easy |

---

## Sysinternals Suite — Key Tools

```powershell
# Download entire suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" `
  -OutFile "SysinternalsSuite.zip"
Expand-Archive SysinternalsSuite.zip -DestinationPath C:\Tools\Sysinternals
```

### Process Explorer (procexp64.exe)

```
Purpose: Enhanced task manager — shows full process tree, DLLs, handles
Key features:
- Colour-coded process highlighting (suspicious: packed, no signature, etc.)
- VirusTotal integration (right-click → Check VirusTotal)
- Replace Task Manager: Options → Replace Task Manager
- Drag crosshair onto window to identify owning process
```

### Process Monitor (Procmon64.exe)

```
Purpose: Real-time file, registry, and network monitoring
Key filters for IR:
- Operation: "CreateFile" + Path contains: \Temp\ → suspicious file creation
- Operation: "RegSetValue" + Path: Run → persistence
- Operation: "TCP Connect" + Remote Address: external → C2 traffic

Filter presets: Filter → Load Filter → Save as "IR-Baseline.PMF"
```

### Autoruns (Autoruns64.exe)

```
Purpose: Most comprehensive autorun location scanner
Key use for IR:
- Check: Hide Microsoft Entries (focus on third-party)
- Options: Scan Options → Check VirusTotal
- Compare: File → Save → Compare to known-good snapshot

Critical tabs:
- Everything (overview)
- Logon (run keys)
- Services
- Scheduled Tasks
- Browser Extensions
- Drivers
```

### PsExec (PSExec64.exe)

```powershell
# Run command on remote system (for incident response)
psexec \\target-hostname cmd.exe

# Copy and run triage script remotely
psexec \\target-hostname -c windows-triage.ps1
```

### TCPView (Tcpview64.exe)

```
Purpose: Real-time network connection viewer with process association
Key features:
- Live view of all TCP/UDP connections
- Process → connection mapping
- Resolve DNS names
- Close connections (right-click)
```

---

## Memory Acquisition

### WinPmem

```powershell
# Acquire memory to file
.\winpmem_mini_x64_rc2.exe memory.dmp

# Acquire memory and stream (for remote capture)
.\winpmem_mini_x64_rc2.exe -

# Verify
Get-FileHash memory.dmp -Algorithm SHA256
```

### DumpIt

```cmd
# Basic usage (run as Admin)
DumpIt.exe

# Specify output
DumpIt.exe /output:C:\evidence\memory.dmp

# Compress output
DumpIt.exe /compress
```

---

## Memory Analysis — Volatility 3 (Windows plugins)

```bash
# Basic analysis commands
python3 vol.py -f memory.dmp windows.info           # System info
python3 vol.py -f memory.dmp windows.pslist         # Process list
python3 vol.py -f memory.dmp windows.pstree         # Process tree (visual)
python3 vol.py -f memory.dmp windows.cmdline        # Command line arguments
python3 vol.py -f memory.dmp windows.dlllist        # DLLs per process
python3 vol.py -f memory.dmp windows.netscan        # Network connections
python3 vol.py -f memory.dmp windows.netstat        # Netstat-style output
python3 vol.py -f memory.dmp windows.handles        # Open handles
python3 vol.py -f memory.dmp windows.filescan       # Files in memory
python3 vol.py -f memory.dmp windows.registry.hivelist  # Registry hives

# Malware-focused
python3 vol.py -f memory.dmp windows.malfind        # Injected/suspicious memory
python3 vol.py -f memory.dmp windows.svcscan        # Service scanning
python3 vol.py -f memory.dmp windows.driverirp      # Driver IRP hooks

# Credential extraction
python3 vol.py -f memory.dmp windows.hashdump       # Local password hashes
python3 vol.py -f memory.dmp windows.lsadump        # LSA secrets

# Dump specific process
python3 vol.py -f memory.dmp -o /evidence/dumps/ windows.dumpfiles --pid 1234
```

---

## Disk Imaging — FTK Imager

```
GUI Procedure:
1. File → Create Disk Image
2. Source: Physical Drive (select target)
3. Image type: E01 (Expert Witness Format — recommended) or RAW (dd)
4. Destination: External evidence drive
5. Enable: Verify images after they are created
6. Enable: Create directory listings

Command line (FTK Imager CLI):
ftkimager.exe \\.\PhysicalDrive0 C:\evidence\disk --e01 --verify
```

---

## KAPE (Kroll Artifact Parser and Extractor)

KAPE is the fastest way to collect relevant forensic artefacts from a live Windows system without a full disk image.

```powershell
# Basic collection (GUI):
kape.exe --tsource C: --tdest C:\evidence\kape --target _BasicCollection

# Recommended targets for IR:
# _BasicCollection     - Common artefacts
# _SANS_Triage         - SANS recommended triage set
# EventLogs            - All event logs
# PowerShellHistory    - PowerShell console history
# ScheduledTasks       - Scheduled task XML files
# WindowsTimeline      - Windows Timeline DB
# BrowserHistory       - Chrome, Firefox, Edge history
# Prefetch             - Prefetch execution artefacts
# USBDevices           - USB connection history

# Module processing (parse collected artefacts):
kape.exe --msource C:\evidence\kape --mdest C:\evidence\kape-parsed `
  --module !EZParser,EvtxECmd,MFTECmd
```

---

## Eric Zimmermann Tools — Artefact Parsing

```powershell
# Get-ZimmermanTools (download all at once)
# https://f001.backblazeb2.com/file/EricZimmermanTools/net6/All_6.zip

# EvtxECmd — Event log parsing
EvtxECmd.exe -d C:\evidence\logs\ --csv C:\evidence\parsed\ --csvf evtx-parsed.csv

# MFTECmd — MFT parsing (file system metadata)
MFTECmd.exe -f C:\evidence\C_MFT --csv C:\evidence\parsed\ --csvf mft.csv

# PECmd — Prefetch parser
PECmd.exe -d C:\Windows\Prefetch --csv C:\evidence\parsed\ --csvf prefetch.csv

# RECmd — Registry parser
RECmd.exe -d C:\evidence\registry\ --bn UsrClass --csv C:\evidence\parsed\

# JLECmd — Jump list parser (recently accessed files)
JLECmd.exe -d "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Recent" `
  --csv C:\evidence\parsed\

# RBCmd — Recycle Bin parser
RBCmd.exe -d C:\$Recycle.Bin --csv C:\evidence\parsed\

# SrumECmd — SRUM (system resource usage) parser
SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv C:\evidence\parsed\

# WxTCmd — Windows Timeline / Activity Cache
WxTCmd.exe -f "C:\Users\%USERNAME%\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db" `
  --csv C:\evidence\parsed\
```

---

## Windows Event Log — Key IDs for IR

```powershell
# Quick security event query — PowerShell
$events = @(
    @{Id=4624; Desc="Successful Logon"},
    @{Id=4625; Desc="Failed Logon"},
    @{Id=4648; Desc="Logon Explicit Credentials"},
    @{Id=4672; Desc="Special Privileges"},
    @{Id=4688; Desc="Process Created"},
    @{Id=4698; Desc="Scheduled Task Created"},
    @{Id=4720; Desc="User Account Created"},
    @{Id=4732; Desc="User Added to Local Admin"},
    @{Id=7045; Desc="New Service Installed"},
    @{Id=1102; Desc="Audit Log Cleared"}
)

foreach ($e in $events) {
    $count = (Get-WinEvent -FilterHashtable @{
        LogName="Security","System"
        Id=$e.Id
        StartTime=(Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue).Count

    Write-Host "$($e.Id) | $($e.Desc) | Count: $count"
}
```

---

## Browser Forensics

```powershell
# Chrome history location
$chromeHistory = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"

# Read with SQLite (copy first — Chrome locks the file)
Copy-Item $chromeHistory C:\evidence\chrome-history.db
# Use: DB Browser for SQLite → SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC

# Edge history
$edgeHistory = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"

# Firefox (uses places.sqlite)
$firefoxProfile = (Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\" -Filter "*.default*").FullName
Copy-Item "$firefoxProfile\places.sqlite" C:\evidence\firefox-history.db
```

---

## Anti-Forensics Detection

```powershell
# Check for timestamp manipulation (Timestomping)
# MFT timestamps vs $STANDARD_INFORMATION vs $FILE_NAME timestamps
# If SI timestamps are earlier than FN timestamps → timestomping suspected
# Use MFTECmd to compare

# Log clearing evidence
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=1102} | Select-Object TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName="System"; Id=104} | Select-Object TimeCreated, Message

# Volume Shadow Copy deletion (ransomware indicator)
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-VSS/Operational"} |
    Where-Object {$_.Message -match "delete"} | Select-Object TimeCreated, Message

# Check for secure delete tools
Get-ChildItem C:\,D:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.Name -match "eraser|sdelete|cipher|wipe"} |
    Select-Object FullName, LastWriteTime
```

---

*Marcus Paula | Independent security engineering lab | Site A*
