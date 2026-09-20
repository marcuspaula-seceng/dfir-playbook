# Live Triage — Linux

> **Author:** Marcus Paula | Independent security engineering lab  
> **Last updated:** 2026-02-23  
> **Classification:** Internal — DFIR Reference  
> **Applies to:** Ubuntu 20.04+, RHEL 8+, CentOS, Debian-based endpoints

---

## Pre-Triage Checklist

- [ ] Written authorisation received
- [ ] Chain of custody form initiated
- [ ] Evidence drive mounted (write-blocked or separate path)
- [ ] Time synchronised (`timedatectl` / `date -u`)
- [ ] Network access to target confirmed or isolated as required
- [ ] Triage script integrity verified (SHA256)

---

## Phase 1 — Volatile Data (Do First — Lost on Reboot)

### 1.1 System Identification

```bash
# Record system time (UTC) immediately
date -u && timedatectl

# System identity
hostname
uname -a
cat /etc/os-release
uptime
```

### 1.2 Network State

```bash
# Active connections (critical — capture immediately)
ss -antpue
netstat -antpue 2>/dev/null

# ARP cache
arp -an
ip neigh

# Routing table
ip route
route -n

# DNS resolution config
cat /etc/resolv.conf
cat /etc/hosts

# Active interfaces
ip addr
ifconfig -a 2>/dev/null

# Firewall rules
iptables -L -n -v 2>/dev/null
nft list ruleset 2>/dev/null
```

### 1.3 Running Processes

```bash
# Full process list with parent relationships
ps auxf
ps -eo pid,ppid,user,stat,start,cmd --forest

# Processes with open network connections
ss -antpe | grep -v LISTEN

# Processes with open files (look for deleted files still open)
lsof -nP 2>/dev/null | grep deleted
lsof -nP 2>/dev/null | grep -i "\.sh\|\.py\|\.pl"

# Hidden processes (compare /proc vs ps)
ls /proc | grep '^[0-9]' | sort -n > /tmp/proc_list.txt
ps aux | awk '{print $2}' | sort -n > /tmp/ps_list.txt
diff /tmp/proc_list.txt /tmp/ps_list.txt
```

### 1.4 Logged-in Users & Sessions

```bash
# Currently logged-in users
w
who
last -n 50
lastlog

# Auth log (recent)
tail -200 /var/log/auth.log 2>/dev/null || tail -200 /var/log/secure 2>/dev/null

# Failed logins
grep "Failed password" /var/log/auth.log | tail -50

# SSH sessions
who | grep pts
```

### 1.5 Loaded Kernel Modules

```bash
lsmod
# Cross-reference against known-good baseline
modinfo $(lsmod | awk 'NR>1{print $1}') 2>/dev/null | grep -E "filename|description"
```

---

## Phase 2 — Persistence Mechanisms

### 2.1 Startup & Scheduled Jobs

```bash
# Cron jobs (all users)
for user in $(cut -d: -f1 /etc/passwd); do
  echo "--- $user ---"
  crontab -u $user -l 2>/dev/null
done

# System crontabs
ls -la /etc/cron* /var/spool/cron/
cat /etc/crontab
ls /etc/cron.d/

# Systemd services (enabled)
systemctl list-units --type=service --state=running
systemctl list-unit-files --state=enabled
```

### 2.2 Privileged Accounts

```bash
# Users with UID 0 (root equivalent)
awk -F: '$3==0{print $1}' /etc/passwd

# Users with sudo access
getent group sudo wheel
cat /etc/sudoers
ls /etc/sudoers.d/

# Recently modified passwd/shadow
stat /etc/passwd /etc/shadow /etc/group
```

### 2.3 SSH Authorised Keys

```bash
find /home /root -name "authorized_keys" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null
```

### 2.4 SUID/SGID Binaries

```bash
# Find unusual SUID/SGID (compare to baseline)
find / -perm /4000 -o -perm /2000 2>/dev/null | sort > /tmp/suid_sgid.txt
cat /tmp/suid_sgid.txt
```

---

## Phase 3 — Filesystem Artefacts

### 3.1 Recently Modified Files

```bash
# Files modified in last 24 hours (system paths)
find /etc /bin /sbin /usr/bin /usr/sbin /tmp /var/tmp -mtime -1 -ls 2>/dev/null

# World-writable directories with files
find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null

# Large files in unusual locations
find /tmp /var/tmp /dev/shm -size +10M 2>/dev/null
```

### 3.2 Shell History

```bash
# Bash history for all users
for user in $(cut -d: -f1 /etc/passwd); do
  home=$(getent passwd $user | cut -d: -f6)
  if [ -f "$home/.bash_history" ]; then
    echo "=== $user ==="
    cat "$home/.bash_history"
  fi
done
```

### 3.3 Installed Packages (Unusual)

```bash
# Packages installed recently
grep " install " /var/log/dpkg.log | tail -50 2>/dev/null
rpm -qa --qf "%{installtime:date} %{name}-%{version}\n" 2>/dev/null | sort | tail -50
```

---

## Phase 4 — Log Collection

```bash
# Key log files
tar -czf /evidence/logs-$(hostname)-$(date +%Y%m%d%H%M%S).tar.gz \
  /var/log/auth.log \
  /var/log/syslog \
  /var/log/kern.log \
  /var/log/dpkg.log \
  /var/log/apache2/ \
  /var/log/nginx/ \
  /var/log/audit/ \
  2>/dev/null
```

---

## Phase 5 — Evidence Preservation

```bash
# Hash all collected evidence
sha256sum /evidence/* > /evidence/SHA256SUMS.txt
md5sum /evidence/* > /evidence/MD5SUMS.txt

# Record investigator notes
echo "Investigator: Marcus Paula | $(date -u)" >> /evidence/case-notes.txt
```

---

## Indicators of Compromise — Linux Red Flags

| Category | Red Flag |
|----------|----------|
| Processes | Process running from `/tmp`, `/dev/shm`, or `/var/tmp` |
| Network | Unexpected outbound connections on unusual ports |
| Users | Extra UID 0 account; modified `/etc/passwd` |
| Cron | Base64-encoded cron entries; cron pointing to `/tmp` |
| Kernel | Unsigned or unknown kernel modules |
| Files | SUID binaries in `/tmp`; recently modified `/etc/passwd` |
| SSH | Unexpected authorised keys; unfamiliar IPs in auth.log |

---

## Automated Script

See: [scripts/bash/linux-triage.sh](../scripts/bash/linux-triage.sh)

---

*Marcus Paula | Independent security engineering lab | Site A*
