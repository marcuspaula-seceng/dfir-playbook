# DFIR Tools Reference — Linux

> **Author:** Marcus Paula | Independent security engineering lab  
> **Last updated:** 2026-02-23  
> **Classification:** Internal — DFIR Reference

---

## Quick Install — Essential DFIR Tools (Ubuntu/Debian)

```bash
sudo apt-get update && sudo apt-get install -y \
  volatility3 \
  tshark wireshark \
  tcpdump \
  nmap \
  strace \
  lsof \
  net-tools \
  curl wget \
  binutils \
  file \
  foremost \
  sleuthkit \
  autopsy \
  dc3dd \
  dcfldd \
  chkrootkit \
  rkhunter \
  yara \
  python3-pip \
  git

# Python tools
pip3 install pefile yara-python volatility3 dfvfs dfwinreg
```

---

## Memory Forensics

### Volatility 3

```bash
# Basic usage
python3 vol.py -f memory.lime windows.pslist          # Process list
python3 vol.py -f memory.lime windows.pstree          # Process tree
python3 vol.py -f memory.lime windows.netscan         # Network connections
python3 vol.py -f memory.lime windows.cmdline         # Command lines
python3 vol.py -f memory.lime windows.filescan        # File scan
python3 vol.py -f memory.lime windows.dumpfiles       # Dump files
python3 vol.py -f memory.lime windows.malfind         # Find injected code
python3 vol.py -f memory.lime windows.handles         # Open handles
python3 vol.py -f memory.lime windows.dlllist         # DLL list per process

# Linux plugins
python3 vol.py -f memory.lime linux.pslist
python3 vol.py -f memory.lime linux.bash              # Bash history from RAM
python3 vol.py -f memory.lime linux.netstat
python3 vol.py -f memory.lime linux.lsof

# Profile detection (Vol2 compatibility mode)
python3 vol.py -f memory.lime imageinfo
```

### LiME (Linux Memory Extractor)

```bash
# Build LiME kernel module
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make

# Capture memory over network (minimal footprint on target)
# On receiving system:
nc -l -p 4444 > /evidence/target-memory.lime

# On target system (run as root):
sudo insmod lime-$(uname -r).ko "path=tcp:4444 format=lime"

# Capture to file (local)
sudo insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"
```

### AVML (Userspace memory acquisition)

```bash
# No kernel module required — userspace acquisition
# Download: https://github.com/microsoft/avml/releases
chmod +x avml
sudo ./avml /evidence/memory.lime
```

---

## Disk Forensics

### Imaging Tools

```bash
# dd (standard)
sudo dd if=/dev/sda of=/evidence/disk.img bs=64k conv=noerror,sync status=progress

# dcfldd (dd with hashing)
sudo dcfldd if=/dev/sda of=/evidence/disk.img bs=64k hash=sha256 hashlog=/evidence/disk.sha256 conv=noerror,sync

# dc3dd (forensic dd)
sudo dc3dd if=/dev/sda of=/evidence/disk.img hof=/evidence/disk.sha256 bs=64k

# Remote imaging over netcat
# On evidence server:
nc -l -p 4445 | dd of=/evidence/remote-disk.img

# On target:
sudo dd if=/dev/sda bs=64k | nc [evidence-server-ip] 4445
```

### The Sleuth Kit (TSK)

```bash
# Mount image read-only
sudo losetup -r /dev/loop0 /evidence/disk.img
sudo mount -r -o loop /evidence/disk.img /mnt/evidence

# TSK commands
mmls disk.img                    # List partitions
fsstat -o [offset] disk.img      # Filesystem stats
fls -r -o [offset] disk.img      # File listing
istat -o [offset] disk.img [inum]  # Inode info

# Recover deleted files
tsk_recover -e /evidence/disk.img /evidence/recovered/

# Timeline generation
fls -r -m "/" -o [offset] disk.img > /evidence/bodyfile.txt
mactime -b /evidence/bodyfile.txt -d > /evidence/timeline.csv
```

### Autopsy (GUI Front-End)

```bash
# Start Autopsy
autopsy

# Access via browser: http://localhost:9999/autopsy
```

---

## Network Forensics

### Wireshark / tshark

```bash
# Capture (live)
sudo tcpdump -i eth0 -w /evidence/capture.pcap

# tshark analysis
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# Filter HTTP traffic
tshark -r capture.pcap -Y "http" -T fields -e http.request.uri -e http.host

# Find DNS queries
tshark -r capture.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name

# Extract files from pcap
tshark -r capture.pcap --export-objects http,/evidence/http-objects/

# Follow TCP stream (connection N)
tshark -r capture.pcap -z follow,tcp,ascii,0
```

### Zeek (Network traffic analysis)

```bash
# Process pcap with Zeek
zeek -r capture.pcap local

# Key log files generated:
# conn.log      — all connections
# http.log      — HTTP requests
# dns.log       — DNS queries
# ssl.log       — TLS connections
# files.log     — file transfers
# weird.log     — protocol anomalies

# Extract unique C2 candidates
cat conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -20
```

---

## Malware Analysis

### FLOSS (Better strings extraction)

```bash
# Install
pip3 install flare-floss

# Basic run (extracts decoded strings from obfuscated malware)
floss malware_sample.exe

# Save output
floss malware_sample.exe > /evidence/floss-output.txt
```

### YARA

```bash
# Scan file
yara rule.yar suspicious_file.exe

# Scan directory recursively
yara -r rule.yar /path/to/scan/

# Scan memory dump
yara rule.yar memory.lime

# Use community rules
git clone https://github.com/Yara-Rules/rules
yara -r rules/malware/ suspicious_file.exe
```

### PE Analysis

```bash
# pefile (Python)
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
print(pe.dump_info())
"

# peframe
pip3 install peframe
peframe sample.exe

# Detect-It-Easy (DIE)
# https://github.com/horsicq/Detect-It-Easy
die sample.exe
```

---

## Log Analysis

### Log parsing (rapid)

```bash
# Auth failures in last hour
grep "Failed password" /var/log/auth.log |
  awk '{print $11}' | sort | uniq -c | sort -rn

# Successful SSH logins
grep "Accepted" /var/log/auth.log | awk '{print $9, $11}'

# New sudo usage
grep "sudo:" /var/log/auth.log | grep -v "session\|pam"

# Root logins
grep "session opened for user root" /var/log/auth.log

# Large log search with ripgrep
rg -z "<EXAMPLE_HOST_IP>" /var/log/
```

### Volatility for Linux log analysis

```bash
# Extract bash history from memory (catches cleared history)
python3 vol.py -f memory.lime linux.bash
```

---

## Useful One-Liners

```bash
# Find world-writable directories
find / -type d -perm -002 -not -path "/proc/*" 2>/dev/null

# Find SUID binaries (all, sort for comparison)
find / -perm /4000 2>/dev/null | sort > suid_binaries.txt

# Check for rootkit indicators
chkrootkit
rkhunter --check --sk

# Network connections by remote IP (count)
ss -ant | awk '{print $5}' | grep -v Address | cut -d: -f1 | sort | uniq -c | sort -rn

# Processes communicating to internet
lsof -nP -iTCP -sTCP:ESTABLISHED | grep -v '127\.\|::1\|10\.\|172\.16\.\|192\.168\.'

# Recently modified files (system paths, last 48h)
find /etc /bin /sbin /usr -mtime -2 -type f -ls 2>/dev/null

# Cron jobs with encoded content
grep -r 'base64\|/tmp\|/dev/shm' /etc/cron* /var/spool/cron 2>/dev/null
```

---

## REMnux — Recommended Analysis Platform

```bash
# REMnux — Linux distro purpose-built for malware analysis
# https://remnux.org

# Install (on existing Ubuntu):
curl -O https://REMnux.org/remnux-cli
mv remnux-cli /usr/local/bin/remnux
chmod +x /usr/local/bin/remnux
remnux install

# Pre-installed highlights:
# - Volatility 2 & 3
# - Radare2 / Cutter
# - FLOSS, pefile, peframe
# - Wireshark / tshark / NetworkMiner
# - YARA + rules
# - Zeek
# - CyberChef (local)
# - Didier Stevens tools (oledump, pdf-parser, etc.)
# - RetDec decompiler
# - Ghidra
```

---

*Marcus Paula | Independent security engineering lab | Site A*
