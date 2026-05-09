#!/bin/bash
# ============================================================
#  CONTAINER RECON SCRIPT
#  Collects all container permission & escape-surface info
#  Output saved to: /tmp/container_recon_report.txt
# ============================================================

OUTPUT="/tmp/container_recon_report.txt"
SEPARATOR="============================================================"

# Colors for terminal (won't appear in file)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log() {
    echo -e "$1" | tee -a "$OUTPUT"
}

section() {
    log "\n$SEPARATOR"
    log "  $1"
    log "$SEPARATOR"
}

run_check() {
    local label="$1"
    local cmd="$2"
    log "\n[ $label ]"
    eval "$cmd" >> "$OUTPUT" 2>&1
    eval "$cmd" 2>/dev/null
}

# ── Init output file ──────────────────────────────────────
echo "" > "$OUTPUT"
log "============================================================"
log "       CONTAINER RECON REPORT"
log "       Generated: $(date)"
log "       Hostname:  $(hostname)"
log "============================================================"


# ── 1. AM I IN A CONTAINER? ──────────────────────────────
section "1. CONTAINER DETECTION"

run_check "Docker env file" "ls -la /.dockerenv 2>/dev/null && echo '[+] /.dockerenv EXISTS → likely Docker' || echo '[-] /.dockerenv not found'"

run_check "cgroup check" "cat /proc/1/cgroup 2>/dev/null"

run_check "Init process (PID 1)" "cat /proc/1/cmdline 2>/dev/null | tr '\0' ' '; echo"

run_check "Container env vars" "env | grep -iE 'docker|kube|container|mesos|rancher|ecs|fargate' 2>/dev/null || echo 'No container-specific env vars found'"

run_check "Overlay filesystem (Docker layers)" "mount | grep overlay 2>/dev/null || echo 'No overlay mount found'"


# ── 2. CURRENT USER ──────────────────────────────────────
section "2. CURRENT USER & IDENTITY"

run_check "whoami" "whoami"
run_check "id" "id"
run_check "groups" "groups"
run_check "/etc/passwd entry" "grep \"^$(whoami):\" /etc/passwd 2>/dev/null"


# ── 3. LINUX CAPABILITIES ────────────────────────────────
section "3. LINUX CAPABILITIES"

run_check "Raw capability hex values" "cat /proc/self/status | grep Cap"

# Decode if capsh is available
if command -v capsh &>/dev/null; then
    CAP_EFF=$(cat /proc/self/status 2>/dev/null | grep CapEff | awk '{print $2}')
    run_check "Decoded effective capabilities" "capsh --decode=$CAP_EFF"
else
    log "\n[!] capsh not found — install libcap2-bin to decode caps"
    log "    Manual decode: https://pkg.go.dev/golang.org/x/sys/unix#pkg-constants"
fi

# Check for dangerous capabilities manually
log "\n[ Dangerous Capability Check ]"
CAP_EFF_HEX=$(cat /proc/self/status 2>/dev/null | grep CapEff | awk '{print $2}')
CAP_EFF_DEC=$(printf "%d" "0x$CAP_EFF_HEX" 2>/dev/null)

check_cap() {
    local name="$1"
    local bit="$2"
    local risk="$3"
    if (( (CAP_EFF_DEC >> bit) & 1 )); then
        log "  [!!!] $name (bit $bit) → PRESENT ← $risk" | tee -a "$OUTPUT"
    else
        log "  [ - ] $name (bit $bit) → not set"
    fi
}

if [[ -n "$CAP_EFF_DEC" ]]; then
    check_cap "CAP_SYS_ADMIN"    21 "Near full host access"
    check_cap "CAP_SYS_PTRACE"   19 "Can inspect/inject host processes"
    check_cap "CAP_SYS_MODULE"   16 "Can load kernel modules"
    check_cap "CAP_SYS_RAWIO"    17 "Raw disk I/O access"
    check_cap "CAP_NET_ADMIN"    12 "Control network interfaces"
    check_cap "CAP_DAC_OVERRIDE"  1 "Bypass file permission checks"
    check_cap "CAP_CHOWN"         0 "Change file ownership"
    check_cap "CAP_SETUID"        7 "Switch to any UID"
    check_cap "CAP_SETGID"        6 "Switch to any GID"
    check_cap "CAP_SYS_CHROOT"   18 "Use chroot — escape potential"
else
    log "  [!] Could not read CapEff value"
fi


# ── 4. PRIVILEGED MODE CHECK ─────────────────────────────
section "4. PRIVILEGED MODE CHECK"

run_check "Seccomp status" "cat /proc/self/status | grep Seccomp
# 0=disabled 1=strict 2=filter"

run_check "AppArmor status" "cat /proc/self/attr/current 2>/dev/null || echo 'AppArmor not readable'"

# Try creating a dummy network interface (only works if privileged)
log "\n[ Privileged network test ]"
if ip link add recon_dummy0 type dummy 2>/dev/null; then
    ip link delete recon_dummy0 2>/dev/null
    log "  [!!!] ip link add SUCCEEDED → PRIVILEGED container" | tee -a "$OUTPUT"
else
    log "  [ - ] ip link add failed → NOT privileged (or restricted)"
fi


# ── 5. FILESYSTEM & MOUNTS ───────────────────────────────
section "5. FILESYSTEM & MOUNTS"

run_check "All mounts" "cat /proc/mounts"

run_check "Interesting mounted paths" "mount | grep -vE 'tmpfs|proc|sysfs|cgroup|devpts|mqueue|hugetlbfs|overlay' 2>/dev/null || echo 'No interesting mounts'"

run_check "Disk layout (df)" "df -h 2>/dev/null"

run_check "Writable directories" "find / -maxdepth 4 -writable -type d 2>/dev/null | grep -vE '/proc|/sys|/dev|/run|/tmp'"


# ── 6. BLOCK DEVICES / RAW DISK ─────────────────────────
section "6. BLOCK DEVICES & RAW DISK ACCESS"

run_check "/dev/sd* devices" "ls -la /dev/sd* 2>/dev/null || echo 'No /dev/sd* found'"
run_check "/dev/nvme* devices" "ls -la /dev/nvme* 2>/dev/null || echo 'No /dev/nvme* found'"
run_check "/dev/vd* devices" "ls -la /dev/vd* 2>/dev/null || echo 'No /dev/vd* found'"
run_check "Full /dev listing" "ls /dev/ 2>/dev/null"

log "\n[ Raw disk read test (1 byte) ]"
for dev in /dev/sda /dev/sda1 /dev/nvme0 /dev/nvme0n1 /dev/vda; do
    if [ -b "$dev" ] 2>/dev/null; then
        if dd if="$dev" bs=1 count=1 of=/dev/null 2>/dev/null; then
            log "  [!!!] READ ACCESS to $dev → raw disk readable!" | tee -a "$OUTPUT"
        else
            log "  [ - ] $dev exists but read denied"
        fi
    fi
done


# ── 7. PROCESS & HOST VISIBILITY ────────────────────────
section "7. PROCESS & HOST VISIBILITY"

run_check "Process list" "ps aux 2>/dev/null || ps -ef 2>/dev/null"

run_check "PID namespace check" "ls -la /proc/1/ns/pid 2>/dev/null"

log "\n[ Host PID namespace test ]"
HOST_PROC_COUNT=$(ls /proc | grep -E '^[0-9]+$' | wc -l)
log "  Visible PIDs: $HOST_PROC_COUNT"
if [ "$HOST_PROC_COUNT" -gt 50 ]; then
    log "  [!] Large number of PIDs — may be seeing host processes"
fi


# ── 8. NETWORK ───────────────────────────────────────────
section "8. NETWORK"

run_check "Network interfaces" "ip addr 2>/dev/null || ifconfig 2>/dev/null"
run_check "Routing table" "ip route 2>/dev/null || route -n 2>/dev/null"
run_check "Open ports" "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"
run_check "DNS config" "cat /etc/resolv.conf 2>/dev/null"
run_check "Hosts file" "cat /etc/hosts 2>/dev/null"


# ── 9. SENSITIVE FILES ───────────────────────────────────
section "9. SENSITIVE FILE ACCESS"

SENSITIVE_FILES=(
    "/etc/shadow"
    "/etc/sudoers"
    "/root/.ssh/id_rsa"
    "/root/.bash_history"
    "/var/run/docker.sock"
    "/run/docker.sock"
    "/run/secrets"
    "/proc/keys"
    "/proc/key-users"
)

log "\n[ Checking sensitive file access ]"
for f in "${SENSITIVE_FILES[@]}"; do
    if [ -e "$f" ]; then
        if [ -r "$f" ]; then
            log "  [!!!] READABLE: $f" | tee -a "$OUTPUT"
        else
            log "  [ e ] EXISTS but not readable: $f"
        fi
    else
        log "  [ - ] Not found: $f"
    fi
done

# Docker socket check (container escape vector)
log "\n[ Docker socket check ]"
if [ -S /var/run/docker.sock ] || [ -S /run/docker.sock ]; then
    log "  [!!!] Docker socket is accessible → CRITICAL escape vector!" | tee -a "$OUTPUT"
    log "        An attacker could run: docker run -v /:/host --privileged alpine chroot /host"
else
    log "  [ - ] Docker socket not accessible"
fi


# ── 10. ENVIRONMENT VARIABLES ────────────────────────────
section "10. ENVIRONMENT VARIABLES"

run_check "All env vars" "env 2>/dev/null"

log "\n[ Sensitive env var check ]"
env 2>/dev/null | grep -iE 'token|secret|password|api_key|aws|gcp|azure|jwt|auth|credential' \
    && log "[!!!] Sensitive values found above!" \
    || log "  [ - ] No obviously sensitive env vars found"


# ── 11. KERNEL INFO ──────────────────────────────────────
section "11. KERNEL & OS INFO"

run_check "Kernel version" "uname -a"
run_check "OS release" "cat /etc/os-release 2>/dev/null"
run_check "CPU info" "cat /proc/cpuinfo | grep 'model name' | head -3"
run_check "Memory info" "cat /proc/meminfo | head -10"


# ── 12. INSTALLED TOOLS ──────────────────────────────────
section "12. USEFUL TOOLS AVAILABLE"

TOOLS=(curl wget python python3 perl ruby nc ncat nmap socat strace ltrace gdb tcpdump tshark git docker kubectl helm aws gcloud az)
log ""
for tool in "${TOOLS[@]}"; do
    path=$(command -v "$tool" 2>/dev/null)
    if [ -n "$path" ]; then
        log "  [+] $tool → $path"
    fi
done


# ── SUMMARY ──────────────────────────────────────────────
section "SUMMARY — ESCAPE SURFACE"

log ""
log "  Review the [!!!] markers above for high-risk findings."
log ""
log "  Key escape vectors to check:"
log "  1. cap_sys_admin present        → mount host fs"
log "  2. Docker socket accessible     → spawn privileged container"
log "  3. /dev/sda readable            → raw disk read"
log "  4. --privileged mode            → full device access"
log "  5. Sensitive volume mounts      → direct host path access"
log "  6. Writable /etc or /proc paths → config manipulation"
log ""
log "  Report saved to: $OUTPUT"
log "  Scan completed:  $(date)"
log "$SEPARATOR"

# ── Done ─────────────────────────────────────────────────
echo ""
echo -e "${GREEN}[✓] Recon complete. Report saved to: $OUTPUT${NC}"
echo -e "${CYAN}    View with: cat $OUTPUT${NC}"
echo -e "${CYAN}    Or:        less $OUTPUT${NC}"
