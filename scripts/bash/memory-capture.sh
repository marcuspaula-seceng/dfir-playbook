#!/usr/bin/env bash
# =============================================================================
# memory-capture.sh — Linux Memory Acquisition
# Author : Marcus Paula | Independent security engineering lab
# Version: 1.0.0
# Date   : 2026-02-23
# Purpose: RAM acquisition using LiME (insmod) or avml (userspace)
#          Part of the DFIR Playbook — github.com/marcuspaula-seceng
# Usage  : sudo bash memory-capture.sh [output_dir] [method: lime|avml|auto]
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OUTPUT_DIR="${1:-/evidence/memory}"
METHOD="${2:-auto}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME=$(hostname)
OUTPUT_FILE="$OUTPUT_DIR/${HOSTNAME}-memory-${TIMESTAMP}.lime"
LOG_FILE="$OUTPUT_DIR/memory-capture-${TIMESTAMP}.log"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[!]${NC} $*" | tee -a "$LOG_FILE" >&2; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
preflight() {
    if [[ $EUID -ne 0 ]]; then
        err "Root required. Exiting."
        exit 1
    fi

    mkdir -p "$OUTPUT_DIR"

    {
        echo "=============================="
        echo " MEMORY ACQUISITION — START"
        echo "=============================="
        echo "Author      : Marcus Paula | Independent security engineering lab"
        echo "Hostname    : $HOSTNAME"
        echo "Kernel      : $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo "RAM total   : $(grep MemTotal /proc/meminfo | awk '{print $2, $3}')"
        echo "Start time  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "Method      : $METHOD"
        echo "Output      : $OUTPUT_FILE"
        echo "=============================="
    } | tee "$LOG_FILE"
}

# ---------------------------------------------------------------------------
# Method detection
# ---------------------------------------------------------------------------
detect_method() {
    if [ "$METHOD" == "auto" ]; then
        if command -v avml &>/dev/null; then
            METHOD="avml"
            log "Auto-detected: avml available"
        elif lsmod | grep -q lime 2>/dev/null; then
            METHOD="lime"
            log "Auto-detected: LiME already loaded"
        else
            warn "No memory acquisition tool found. Falling back to /proc/kcore"
            METHOD="kcore"
        fi
    fi
    log "Method selected: $METHOD"
}

# ---------------------------------------------------------------------------
# Capture methods
# ---------------------------------------------------------------------------
capture_avml() {
    log "Capturing memory with avml..."
    avml "$OUTPUT_FILE"
    log "avml capture complete."
}

capture_lime() {
    local lime_module
    lime_module=$(find /lib/modules /tmp -name "lime*.ko" 2>/dev/null | head -1)

    if [ -z "$lime_module" ]; then
        err "LiME kernel module not found."
        err "Build LiME for kernel $(uname -r) and place .ko in /tmp/"
        err "  git clone https://github.com/504ensicsLabs/LiME"
        err "  cd LiME/src && make"
        exit 1
    fi

    log "Loading LiME module: $lime_module"
    insmod "$lime_module" "path=$OUTPUT_FILE format=lime"
    sleep 5

    # LiME writes to the path; wait for completion
    local prev_size=0
    local cur_size
    while true; do
        cur_size=$(stat -c%s "$OUTPUT_FILE" 2>/dev/null || echo 0)
        if [ "$cur_size" -eq "$prev_size" ] && [ "$cur_size" -gt 0 ]; then
            break
        fi
        prev_size=$cur_size
        sleep 2
    done

    log "Removing LiME module..."
    rmmod lime 2>/dev/null || true
    log "LiME capture complete."
}

capture_kcore() {
    warn "Using /proc/kcore — less reliable, incomplete on some kernels"
    local ram_kb
    ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_bytes=$(( ram_kb * 1024 ))

    log "RAM size: $ram_bytes bytes"
    log "Copying /proc/kcore (limited to RAM size)..."
    dd if=/proc/kcore of="${OUTPUT_FILE}.kcore" bs=4M count=$(( ram_bytes / (4*1024*1024) )) 2>&1 | tee -a "$LOG_FILE" || true
    log "kcore copy done (may be incomplete)."
}

# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------
hash_image() {
    log "Hashing memory image (SHA256)..."
    sha256sum "$OUTPUT_FILE" >> "$OUTPUT_DIR/SHA256SUMS.txt" 2>/dev/null || \
    sha256sum "${OUTPUT_FILE}.kcore" >> "$OUTPUT_DIR/SHA256SUMS.txt" 2>/dev/null || true
    log "Hash recorded."
}

# ---------------------------------------------------------------------------
# Finish
# ---------------------------------------------------------------------------
finish() {
    local img="${OUTPUT_FILE}"
    [ ! -f "$img" ] && img="${OUTPUT_FILE}.kcore"

    if [ -f "$img" ]; then
        local size
        size=$(ls -lh "$img" | awk '{print $5}')
        log "Image size  : $size"
        log "Output file : $img"
        log "End time    : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
        echo "Next step: analyse with Volatility"
        echo "  python3 vol.py -f $img imageinfo"
        echo "  python3 vol.py -f $img --profile=<profile> pslist"
    else
        err "Memory image not found — capture may have failed."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    preflight
    detect_method

    case "$METHOD" in
        avml)  capture_avml ;;
        lime)  capture_lime ;;
        kcore) capture_kcore ;;
        *) err "Unknown method: $METHOD"; exit 1 ;;
    esac

    hash_image
    finish
}

main "$@"
