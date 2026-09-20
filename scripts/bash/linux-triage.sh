#!/usr/bin/env bash
# =============================================================================
# linux-triage.sh — Linux Live Triage Script
# Author : Marcus Paula | Independent security engineering lab
# Version: 1.0.0
# Date   : 2026-02-23
# Purpose: Automated volatile evidence collection from Linux systems
#          Part of the DFIR Playbook — github.com/marcuspaula-seceng
# Usage  : sudo bash linux-triage.sh [evidence_dir]
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
EVIDENCE_DIR="${1:-/evidence/$(hostname)-$(date +%Y%m%d-%H%M%S)}"
SCRIPT_VERSION="1.0.0"
INVESTIGATOR="Marcus Paula | Independent security engineering lab"
CASE_ID="${CASE_ID:-UNSET}"

# ---------------------------------------------------------------------------
# Colour output
# ---------------------------------------------------------------------------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[!]${NC} $*" >&2; }
hdr()  { echo -e "\n${CYAN}=== $* ===${NC}"; }

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
preflight() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root. Exiting."
        exit 1
    fi

    mkdir -p "$EVIDENCE_DIR"/{network,processes,users,persistence,logs,filesystem}
    log "Evidence directory: $EVIDENCE_DIR"

    # Record start time
    {
        echo "=============================="
        echo " LINUX TRIAGE — START"
        echo "=============================="
        echo "Investigator : $INVESTIGATOR"
        echo "Script ver.  : $SCRIPT_VERSION"
        echo "Case ID      : $CASE_ID"
        echo "Hostname     : $(hostname)"
        echo "Triage start : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "Kernel       : $(uname -r)"
        echo "Distro       : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
        echo "=============================="
    } | tee "$EVIDENCE_DIR/triage-metadata.txt"
}

# ---------------------------------------------------------------------------
# Volatile — Network State
# ---------------------------------------------------------------------------
collect_network() {
    hdr "Network State"

    log "Active connections (ss)..."
    ss -antpue 2>/dev/null > "$EVIDENCE_DIR/network/ss-connections.txt"

    log "ARP cache..."
    arp -an 2>/dev/null > "$EVIDENCE_DIR/network/arp-cache.txt"
    ip neigh 2>/dev/null >> "$EVIDENCE_DIR/network/arp-cache.txt"

    log "Routing table..."
    ip route 2>/dev/null > "$EVIDENCE_DIR/network/routing-table.txt"

    log "Network interfaces..."
    ip addr 2>/dev/null > "$EVIDENCE_DIR/network/interfaces.txt"

    log "DNS configuration..."
    cat /etc/resolv.conf 2>/dev/null > "$EVIDENCE_DIR/network/resolv.conf"
    cat /etc/hosts 2>/dev/null > "$EVIDENCE_DIR/network/hosts"

    log "Firewall rules..."
    iptables -L -n -v 2>/dev/null > "$EVIDENCE_DIR/network/iptables.txt" || true
    nft list ruleset 2>/dev/null > "$EVIDENCE_DIR/network/nftables.txt" || true

    log "Network done."
}

# ---------------------------------------------------------------------------
# Volatile — Processes
# ---------------------------------------------------------------------------
collect_processes() {
    hdr "Running Processes"

    log "Full process list..."
    ps auxf 2>/dev/null > "$EVIDENCE_DIR/processes/ps-tree.txt"
    ps -eo pid,ppid,user,stat,start,cmd 2>/dev/null > "$EVIDENCE_DIR/processes/ps-full.txt"

    log "Open files (lsof)..."
    lsof -nP 2>/dev/null > "$EVIDENCE_DIR/processes/lsof-all.txt" || warn "lsof not available"

    log "Deleted files still open..."
    lsof -nP 2>/dev/null | grep -i deleted > "$EVIDENCE_DIR/processes/lsof-deleted.txt" || true

    log "Loaded kernel modules..."
    lsmod > "$EVIDENCE_DIR/processes/lsmod.txt"

    log "Processes done."
}

# ---------------------------------------------------------------------------
# Volatile — Users & Sessions
# ---------------------------------------------------------------------------
collect_users() {
    hdr "Users and Sessions"

    log "Logged-in users..."
    w 2>/dev/null > "$EVIDENCE_DIR/users/w.txt"
    who 2>/dev/null > "$EVIDENCE_DIR/users/who.txt"
    last -n 100 2>/dev/null > "$EVIDENCE_DIR/users/last.txt"
    lastlog 2>/dev/null > "$EVIDENCE_DIR/users/lastlog.txt"

    log "User accounts..."
    cat /etc/passwd > "$EVIDENCE_DIR/users/passwd.txt"
    cat /etc/group  > "$EVIDENCE_DIR/users/group.txt"

    log "Sudo access..."
    cat /etc/sudoers 2>/dev/null > "$EVIDENCE_DIR/users/sudoers.txt" || true
    ls -la /etc/sudoers.d/ 2>/dev/null >> "$EVIDENCE_DIR/users/sudoers.txt" || true

    log "SSH authorised keys..."
    find /home /root -name "authorized_keys" -exec echo "=== {} ===" \; \
        -exec cat {} \; 2>/dev/null > "$EVIDENCE_DIR/users/ssh-authorized-keys.txt"

    log "Users done."
}

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
collect_persistence() {
    hdr "Persistence Mechanisms"

    log "Cron jobs..."
    {
        echo "=== /etc/crontab ==="
        cat /etc/crontab 2>/dev/null
        echo ""
        echo "=== /etc/cron.d/ ==="
        ls -la /etc/cron.d/ 2>/dev/null
        for f in /etc/cron.d/*; do [ -f "$f" ] && echo "--- $f ---" && cat "$f"; done 2>/dev/null
        echo ""
        echo "=== User crontabs ==="
        for user in $(cut -d: -f1 /etc/passwd); do
            cron=$(crontab -u "$user" -l 2>/dev/null)
            if [ -n "$cron" ]; then echo "--- $user ---"; echo "$cron"; fi
        done
    } > "$EVIDENCE_DIR/persistence/crontabs.txt"

    log "Systemd services (running)..."
    systemctl list-units --type=service --state=running --no-pager 2>/dev/null \
        > "$EVIDENCE_DIR/persistence/systemd-running.txt"

    log "Systemd services (enabled)..."
    systemctl list-unit-files --state=enabled --no-pager 2>/dev/null \
        > "$EVIDENCE_DIR/persistence/systemd-enabled.txt"

    log "SUID/SGID binaries..."
    find / -perm /4000 -o -perm /2000 2>/dev/null | sort \
        > "$EVIDENCE_DIR/persistence/suid-sgid.txt"

    log "Persistence done."
}

# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------
collect_filesystem() {
    hdr "Filesystem Artefacts"

    log "Recently modified files in suspicious locations (last 24h)..."
    find /tmp /var/tmp /dev/shm -type f -mtime -1 -ls 2>/dev/null \
        > "$EVIDENCE_DIR/filesystem/suspicious-recent-files.txt"

    log "Files in /tmp, /var/tmp, /dev/shm..."
    ls -laR /tmp /var/tmp /dev/shm 2>/dev/null \
        > "$EVIDENCE_DIR/filesystem/temp-dirs.txt"

    log "Shell histories..."
    {
        for user in $(cut -d: -f1 /etc/passwd); do
            home=$(getent passwd "$user" | cut -d: -f6)
            for hist in .bash_history .zsh_history .sh_history; do
                if [ -f "$home/$hist" ]; then
                    echo "=== $user : $home/$hist ==="
                    cat "$home/$hist" 2>/dev/null
                fi
            done
        done
    } > "$EVIDENCE_DIR/filesystem/shell-histories.txt"

    log "Filesystem done."
}

# ---------------------------------------------------------------------------
# Log collection
# ---------------------------------------------------------------------------
collect_logs() {
    hdr "System Logs"

    log "Copying key log files..."
    for logfile in /var/log/auth.log /var/log/secure /var/log/syslog \
                   /var/log/messages /var/log/kern.log /var/log/dpkg.log; do
        [ -f "$logfile" ] && cp "$logfile" "$EVIDENCE_DIR/logs/" 2>/dev/null
    done

    log "Audit log..."
    [ -d /var/log/audit ] && cp -r /var/log/audit "$EVIDENCE_DIR/logs/" 2>/dev/null || true

    log "Logs done."
}

# ---------------------------------------------------------------------------
# Integrity — hash all collected evidence
# ---------------------------------------------------------------------------
hash_evidence() {
    hdr "Evidence Integrity"

    log "Generating SHA256 hashes..."
    find "$EVIDENCE_DIR" -type f -not -name "*.sha256" \
        -exec sha256sum {} \; > "$EVIDENCE_DIR/SHA256SUMS.txt"

    log "SHA256SUMS.txt written."
}

# ---------------------------------------------------------------------------
# Finish
# ---------------------------------------------------------------------------
finish() {
    hdr "Triage Complete"
    {
        echo "Triage end  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "Evidence dir: $EVIDENCE_DIR"
        echo "Files collected: $(find "$EVIDENCE_DIR" -type f | wc -l)"
    } | tee -a "$EVIDENCE_DIR/triage-metadata.txt"

    echo ""
    log "Evidence stored in: $EVIDENCE_DIR"
    log "Hash manifest: $EVIDENCE_DIR/SHA256SUMS.txt"
    warn "Remember to document chain of custody."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    preflight
    collect_network
    collect_processes
    collect_users
    collect_persistence
    collect_filesystem
    collect_logs
    hash_evidence
    finish
}

main "$@"
