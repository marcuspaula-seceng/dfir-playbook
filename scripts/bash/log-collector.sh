#!/usr/bin/env bash
# =============================================================================
# log-collector.sh — Centralised Log Harvesting (Linux)
# Author : Marcus Paula | Independent security engineering lab
# Version: 1.0.0
# Date   : 2026-02-23
# Purpose: Collect, compress, and hash system logs for DFIR evidence
#          Part of the DFIR Playbook — github.com/marcuspaula-seceng
# Usage  : sudo bash log-collector.sh [output_dir] [hours_back]
# =============================================================================

set -euo pipefail

OUTPUT_DIR="${1:-/evidence/logs}"
HOURS_BACK="${2:-72}"
HOSTNAME=$(hostname)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="$OUTPUT_DIR/${HOSTNAME}-logs-${TIMESTAMP}.tar.gz"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[!]${NC} $*" >&2; }
hdr()  { echo -e "\n${CYAN}=== $* ===${NC}"; }

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

preflight() {
    [[ $EUID -ne 0 ]] && { err "Root required."; exit 1; }
    mkdir -p "$OUTPUT_DIR"
    log "Collecting logs from last ${HOURS_BACK} hours"
    log "Staging  : $STAGING"
    log "Output   : $ARCHIVE"
}

collect_standard_logs() {
    hdr "Standard System Logs"
    mkdir -p "$STAGING/system"

    local logs=(
        /var/log/auth.log
        /var/log/secure
        /var/log/syslog
        /var/log/messages
        /var/log/kern.log
        /var/log/dmesg
        /var/log/boot.log
        /var/log/dpkg.log
        /var/log/apt/history.log
        /var/log/yum.log
        /var/log/dnf.log
    )

    for log_file in "${logs[@]}"; do
        if [ -f "$log_file" ]; then
            cp "$log_file" "$STAGING/system/" 2>/dev/null && log "Copied: $log_file"
            # Also copy rotated versions
            for rotated in "${log_file}".1 "${log_file}".2 "${log_file}"-*.gz; do
                [ -f "$rotated" ] && cp "$rotated" "$STAGING/system/" 2>/dev/null
            done
        fi
    done
}

collect_audit_logs() {
    hdr "Audit Logs"
    if [ -d /var/log/audit ]; then
        mkdir -p "$STAGING/audit"
        cp -r /var/log/audit/* "$STAGING/audit/" 2>/dev/null
        log "Audit logs collected."
    else
        warn "Audit log directory not found (/var/log/audit)"
    fi
}

collect_application_logs() {
    hdr "Application Logs"
    mkdir -p "$STAGING/application"

    local app_log_dirs=(
        /var/log/apache2
        /var/log/nginx
        /var/log/mysql
        /var/log/postgresql
        /var/log/redis
        /var/log/mongodb
        /var/log/cron
    )

    for dir in "${app_log_dirs[@]}"; do
        if [ -d "$dir" ]; then
            cp -r "$dir" "$STAGING/application/" 2>/dev/null && log "Collected: $dir"
        fi
    done
}

collect_systemd_journal() {
    hdr "Systemd Journal"
    mkdir -p "$STAGING/journal"

    if command -v journalctl &>/dev/null; then
        log "Exporting journal (last ${HOURS_BACK}h) to JSON..."
        journalctl --since "-${HOURS_BACK}h" --output=json \
            > "$STAGING/journal/journal-recent.json" 2>/dev/null || true

        log "Exporting boot journals..."
        journalctl --list-boots --no-pager 2>/dev/null \
            > "$STAGING/journal/boot-list.txt" || true

        log "Exporting kernel messages..."
        journalctl -k --no-pager --since "-${HOURS_BACK}h" \
            > "$STAGING/journal/kernel-recent.txt" 2>/dev/null || true

        log "Exporting auth events..."
        journalctl --since "-${HOURS_BACK}h" \
            -u sshd -u sudo -u su --no-pager \
            > "$STAGING/journal/auth-events.txt" 2>/dev/null || true
    else
        warn "journalctl not available on this system."
    fi
}

collect_recently_modified() {
    hdr "Recently Modified Logs"
    mkdir -p "$STAGING/recently-modified"

    log "Finding log files modified in last ${HOURS_BACK}h..."
    find /var/log -type f -mmin "-$(( HOURS_BACK * 60 ))" 2>/dev/null |
        while read -r f; do
            rel_path="${f#/var/log/}"
            dir_part=$(dirname "$STAGING/recently-modified/$rel_path")
            mkdir -p "$dir_part"
            cp "$f" "$STAGING/recently-modified/$rel_path" 2>/dev/null || true
        done
}

create_archive() {
    hdr "Creating Archive"

    log "Compressing to: $ARCHIVE"
    tar -czf "$ARCHIVE" -C "$(dirname "$STAGING")" "$(basename "$STAGING")"

    log "Hashing archive..."
    sha256sum "$ARCHIVE" >> "$OUTPUT_DIR/SHA256SUMS.txt"

    local size
    size=$(ls -lh "$ARCHIVE" | awk '{print $5}')
    log "Archive size: $size"
}

generate_manifest() {
    local manifest="$OUTPUT_DIR/log-manifest-${TIMESTAMP}.txt"
    {
        echo "=============================="
        echo " LOG COLLECTION MANIFEST"
        echo "=============================="
        echo "Author     : Marcus Paula | Independent security engineering lab"
        echo "Hostname   : $HOSTNAME"
        echo "Collected  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "Hours back : $HOURS_BACK"
        echo "Archive    : $ARCHIVE"
        echo ""
        echo "--- Files Collected ---"
        find "$STAGING" -type f | sort | sed "s|$STAGING/||"
        echo ""
        echo "--- Counts ---"
        echo "Total files: $(find "$STAGING" -type f | wc -l)"
        echo "Total size : $(du -sh "$STAGING" | cut -f1)"
    } > "$manifest"
    log "Manifest: $manifest"
}

main() {
    preflight
    collect_standard_logs
    collect_audit_logs
    collect_application_logs
    collect_systemd_journal
    collect_recently_modified
    generate_manifest
    create_archive
    log "Log collection complete."
    log "Archive: $ARCHIVE"
}

main "$@"
