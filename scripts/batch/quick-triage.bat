@echo off
:: =============================================================================
:: quick-triage.bat — Quick Windows Triage (No PowerShell policy required)
:: Author : Marcus Paula | Independent security engineering lab
:: Version: 1.0.0
:: Date   : 2026-02-23
:: Purpose: Rapid triage using built-in Windows commands only
::          Useful when PowerShell execution policy is restricted
::          Part of the DFIR Playbook — github.com/marcuspaula-seceng
:: Usage  : Run as Administrator — double-click or: quick-triage.bat [output_drive]
:: =============================================================================

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

:: ---------------------------------------------------------------------------
:: Setup
:: ---------------------------------------------------------------------------
set DRIVE=%1
if "%DRIVE%"=="" set DRIVE=C:

for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set dt=%%a
set TIMESTAMP=%dt:~0,8%-%dt:~8,6%
set HOSTNAME=%COMPUTERNAME%
set OUTDIR=%DRIVE%\DFIR-%HOSTNAME%-%TIMESTAMP%

mkdir "%OUTDIR%" 2>nul
mkdir "%OUTDIR%\network" 2>nul
mkdir "%OUTDIR%\processes" 2>nul
mkdir "%OUTDIR%\users" 2>nul
mkdir "%OUTDIR%\persistence" 2>nul
mkdir "%OUTDIR%\system" 2>nul

echo.
echo ==============================
echo  QUICK WINDOWS TRIAGE
echo  Marcus Paula / Independent security engineering lab IT
echo ==============================
echo  Host     : %HOSTNAME%
echo  Output   : %OUTDIR%
echo  Time     : %TIMESTAMP%
echo ==============================
echo.

echo [+] Starting triage — DO NOT reboot the system

:: ---------------------------------------------------------------------------
:: Record start time
:: ---------------------------------------------------------------------------
echo ============================== > "%OUTDIR%\triage-metadata.txt"
echo  QUICK TRIAGE METADATA >> "%OUTDIR%\triage-metadata.txt"
echo ============================== >> "%OUTDIR%\triage-metadata.txt"
echo Author   : Marcus Paula / Independent security engineering lab IT >> "%OUTDIR%\triage-metadata.txt"
echo Hostname : %HOSTNAME% >> "%OUTDIR%\triage-metadata.txt"
echo Date     : %dt% >> "%OUTDIR%\triage-metadata.txt"
echo Output   : %OUTDIR% >> "%OUTDIR%\triage-metadata.txt"
echo ============================== >> "%OUTDIR%\triage-metadata.txt"

:: ---------------------------------------------------------------------------
:: NETWORK — Collect first (most volatile)
:: ---------------------------------------------------------------------------
echo [+] Network state...

echo === NETSTAT -ANO === > "%OUTDIR%\network\netstat.txt"
netstat -ano >> "%OUTDIR%\network\netstat.txt"

echo === NETSTAT -ANB (with process names) === >> "%OUTDIR%\network\netstat.txt"
netstat -anb >> "%OUTDIR%\network\netstat.txt" 2>nul

echo === ARP TABLE === > "%OUTDIR%\network\arp.txt"
arp -a >> "%OUTDIR%\network\arp.txt"

echo === ROUTE TABLE === > "%OUTDIR%\network\route.txt"
route print >> "%OUTDIR%\network\route.txt"

echo === IPCONFIG ALL === > "%OUTDIR%\network\ipconfig.txt"
ipconfig /all >> "%OUTDIR%\network\ipconfig.txt"

echo === DNS CACHE === > "%OUTDIR%\network\dns-cache.txt"
ipconfig /displaydns >> "%OUTDIR%\network\dns-cache.txt"

echo === HOSTS FILE === > "%OUTDIR%\network\hosts.txt"
type %SystemRoot%\System32\drivers\etc\hosts >> "%OUTDIR%\network\hosts.txt"

echo [+] Network done.

:: ---------------------------------------------------------------------------
:: PROCESSES
:: ---------------------------------------------------------------------------
echo [+] Processes...

echo === TASKLIST === > "%OUTDIR%\processes\tasklist.txt"
tasklist /v >> "%OUTDIR%\processes\tasklist.txt"

echo === TASKLIST WITH MODULES === > "%OUTDIR%\processes\tasklist-modules.txt"
tasklist /m >> "%OUTDIR%\processes\tasklist-modules.txt" 2>nul

echo === TASKLIST WITH SERVICES === > "%OUTDIR%\processes\tasklist-services.txt"
tasklist /svc >> "%OUTDIR%\processes\tasklist-services.txt"

echo === WMIC PROCESS === > "%OUTDIR%\processes\wmic-process.txt"
wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine /format:csv >> "%OUTDIR%\processes\wmic-process.txt"

echo [+] Processes done.

:: ---------------------------------------------------------------------------
:: SERVICES
:: ---------------------------------------------------------------------------
echo [+] Services...

echo === SC QUERY === > "%OUTDIR%\processes\services.txt"
sc query type= all >> "%OUTDIR%\processes\services.txt"

echo === WMIC SERVICE === > "%OUTDIR%\processes\services-wmic.txt"
wmic service get Name,StartMode,State,PathName /format:csv >> "%OUTDIR%\processes\services-wmic.txt"

echo [+] Services done.

:: ---------------------------------------------------------------------------
:: USERS
:: ---------------------------------------------------------------------------
echo [+] Users and sessions...

echo === NET USER === > "%OUTDIR%\users\users.txt"
net user >> "%OUTDIR%\users\users.txt"

echo === LOCAL ADMINS === > "%OUTDIR%\users\local-admins.txt"
net localgroup administrators >> "%OUTDIR%\users\local-admins.txt"

echo === QUERY USER === > "%OUTDIR%\users\sessions.txt"
query user >> "%OUTDIR%\users\sessions.txt" 2>nul

echo === QUERY SESSION === >> "%OUTDIR%\users\sessions.txt"
query session >> "%OUTDIR%\users\sessions.txt" 2>nul

echo === NET SESSION === > "%OUTDIR%\users\net-sessions.txt"
net session >> "%OUTDIR%\users\net-sessions.txt" 2>nul

echo [+] Users done.

:: ---------------------------------------------------------------------------
:: PERSISTENCE — AUTORUN KEYS
:: ---------------------------------------------------------------------------
echo [+] Persistence (registry)...

echo === HKLM RUN === > "%OUTDIR%\persistence\registry-run.txt"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%OUTDIR%\persistence\registry-run.txt" 2>nul

echo === HKCU RUN === >> "%OUTDIR%\persistence\registry-run.txt"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%OUTDIR%\persistence\registry-run.txt" 2>nul

echo === HKLM RUNONCE === >> "%OUTDIR%\persistence\registry-run.txt"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" >> "%OUTDIR%\persistence\registry-run.txt" 2>nul

echo === HKCU RUNONCE === >> "%OUTDIR%\persistence\registry-run.txt"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" >> "%OUTDIR%\persistence\registry-run.txt" 2>nul

echo === WOW6432 RUN === >> "%OUTDIR%\persistence\registry-run.txt"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" >> "%OUTDIR%\persistence\registry-run.txt" 2>nul

echo === WINLOGON === >> "%OUTDIR%\persistence\registry-run.txt"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" >> "%OUTDIR%\persistence\registry-run.txt" 2>nul

echo === SCHEDULED TASKS === > "%OUTDIR%\persistence\scheduled-tasks.txt"
schtasks /query /fo LIST /v >> "%OUTDIR%\persistence\scheduled-tasks.txt"

echo [+] Persistence done.

:: ---------------------------------------------------------------------------
:: SYSTEM INFO
:: ---------------------------------------------------------------------------
echo [+] System information...

echo === SYSTEMINFO === > "%OUTDIR%\system\systeminfo.txt"
systeminfo >> "%OUTDIR%\system\systeminfo.txt"

echo === ENVIRONMENT VARIABLES === > "%OUTDIR%\system\environment.txt"
set >> "%OUTDIR%\system\environment.txt"

echo === HOTFIXES === > "%OUTDIR%\system\hotfixes.txt"
wmic qfe list >> "%OUTDIR%\system\hotfixes.txt"

echo === INSTALLED SOFTWARE === > "%OUTDIR%\system\installed-software.txt"
wmic product get Name,Version,InstallDate /format:csv >> "%OUTDIR%\system\installed-software.txt"

echo === SHARED FOLDERS === > "%OUTDIR%\system\shares.txt"
net share >> "%OUTDIR%\system\shares.txt"

echo === OPEN FILES === > "%OUTDIR%\system\open-files.txt"
openfiles >> "%OUTDIR%\system\open-files.txt" 2>nul

echo [+] System info done.

:: ---------------------------------------------------------------------------
:: HASH EVIDENCE
:: ---------------------------------------------------------------------------
echo [+] Hashing evidence files...

echo SHA256 Hashes > "%OUTDIR%\SHA256SUMS.txt"
echo Generated: %dt% >> "%OUTDIR%\SHA256SUMS.txt"
echo. >> "%OUTDIR%\SHA256SUMS.txt"

for /r "%OUTDIR%" %%F in (*) do (
    certutil -hashfile "%%F" SHA256 2>nul | find /v "CertUtil" | find /v "successfully" >> "%OUTDIR%\SHA256SUMS.txt"
    echo %%F >> "%OUTDIR%\SHA256SUMS.txt"
)

:: ---------------------------------------------------------------------------
:: DONE
:: ---------------------------------------------------------------------------
echo.
echo ==============================
echo  TRIAGE COMPLETE
echo ==============================
echo  Evidence: %OUTDIR%
echo  Complete chain of custody form
echo ==============================
echo.
pause
