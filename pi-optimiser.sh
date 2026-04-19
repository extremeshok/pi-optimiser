#!/usr/bin/env bash
# ======================================================================
# Coded by Adrian Jon Kriel :: admin@extremeshok.com
# Project home: https://github.com/extremeshok/pi-optimiser
# ======================================================================
# pi-optimiser.sh :: version 7.5
#======================================================================
# One-shot optimiser for Raspberry Pi OS desktops. Key capabilities:
#   - Removes bundled bloatware and trims apt caches for a lean install
#   - Tunes filesystems, tmpfs mounts, and journaling to minimise SD wear
#   - Hardens apt/systemd/autoupdate behaviour for predictable uptime
#   - Installs core CLI tooling plus optional extras like Tailscale/Docker
#   - Configures security-only unattended upgrades on a six-hour cadence
#   - Applies kernel/sysctl tweaks, raises file limits, and enables routing
#   - Adds display-friendly defaults (screen, KMS) that suit kiosks or can be skipped
#======================================================================
# Requirements:
#   - Raspberry Pi OS (Bookworm/Trixie or newer) with systemd
#   - Run as root (sudo ./pi-optimiser.sh)
# ======================================================================
set -euo pipefail

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
  echo "pi-optimiser.sh requires Bash 4.0 or newer." >&2
  exit 1
fi

SCRIPT_NAME=$(basename "$0")
SCRIPT_VERSION="7.5"

MARKER_DIR="/etc/pi-optimiser"
STATE_FILE="$MARKER_DIR/state"
LOG_FILE="/var/log/pi-optimiser.log"
APT_CONF_FILE="/etc/apt/apt.conf.d/20pi-optimiser"
SYSCTL_CONF_FILE="/etc/sysctl.d/99-pi-optimiser.conf"
JOURNALD_CONF_FILE="/etc/systemd/journald.conf.d/99-pi-optimiser.conf"
TAILSCALE_LIST_FILE="/etc/apt/sources.list.d/tailscale.list"
TAILSCALE_KEY_FILE="/usr/share/keyrings/tailscale-archive-keyring.gpg"
TMPFS_ENTRY="tmpfs /tmp tmpfs defaults,nosuid,nodev,size=200m 0 0"
DOCKER_LIST_FILE="/etc/apt/sources.list.d/docker.list"
DOCKER_KEY_FILE="/etc/apt/keyrings/docker-archive-keyring.gpg"
CMDLINE_FILE="/boot/firmware/cmdline.txt"
CONFIG_TXT_FILE="/boot/firmware/config.txt"
LIGHTDM_NOBLANK_FILE="/etc/lightdm/lightdm.conf.d/99-pi-optimiser-no-blanking.conf"
VAR_LOG_TMPFS_ENTRY="tmpfs /var/log tmpfs defaults,nosuid,nodev,mode=0755,size=50m 0 0"
VAR_LOG_TMPFILES="/etc/tmpfiles.d/pi-optimiser-varlog.conf"
LIMITS_CONF_FILE="/etc/security/limits.d/99-pi-optimiser.conf"
SYSTEMD_SYSTEM_LIMITS="/etc/systemd/system.conf.d/99-pi-optimiser.conf"
SYSTEMD_USER_LIMITS="/etc/systemd/user.conf.d/99-pi-optimiser.conf"
CONFIG_OPTIMISER_STATE="/etc/pi-optimiser/config-optimisations.json"
UNATTENDED_CONF_FILE="/etc/apt/apt.conf.d/51pi-optimiser-unattended.conf"
UNATTENDED_SERVICE="/etc/systemd/system/pi-unattended-upgrades.service"
UNATTENDED_TIMER="/etc/systemd/system/pi-unattended-upgrades.timer"
ZRAM_CONF_FILE="/etc/systemd/zram-generator.conf"
CPU_GOVERNOR_SERVICE="/etc/systemd/system/pi-optimiser-cpu-governor.service"
EEPROM_STAGING_DIR="/etc/pi-optimiser/eeprom"

FORCE=0
KEEP_SCREEN_BLANKING=0
DRY_RUN=0
STATUS_ONLY=0
LIST_TASKS=0
INSTALL_TAILSCALE=0
INSTALL_DOCKER=0
REQUESTED_LOCALE=""
PROXY_BACKEND=""
ZRAM_ALGO_OVERRIDE=""
INSTALL_ZRAM=0
REQUEST_OC_CONSERVATIVE=0
SECURE_SSH=0
FIRMWARE_UPDATE=0
EEPROM_UPDATE=0
INSTALL_WATCHDOG=0
INSTALL_PI5_FAN_PROFILE=0
REQUESTED_TIMEZONE=""
REQUESTED_HOSTNAME=""
SSH_IMPORT_GITHUB=""
SSH_IMPORT_URL=""

APT_UPDATED=0
CURRENT_TASK=""
OS_ID=""
OS_ID_LIKE=""
OS_CODENAME=""

SYSTEM_MODEL=""
SYSTEM_PI_GEN=""
SYSTEM_RAM_MB=0
SYSTEM_BOOT_DEVICE=""
SYSTEM_KERNEL=""
SYSTEM_FIRMWARE=""

declare -a PRECHECK_WARNINGS=()
declare -a PRECHECK_BLOCKERS=()
POWER_HEALTHY=1
NETWORK_AVAILABLE=1

declare -A BACKED_UP=()
declare -A SKIP_TASKS=()
declare -a ONLY_TASKS=()
declare -a SUMMARY_COMPLETED=()
declare -a SUMMARY_SKIPPED=()
declare -a SUMMARY_FAILED=()
# Tasks skipped if power/thermal preflight reports a blocker.
declare -a POWER_SENSITIVE_TASKS=(boot_config libliftoff oc_conservative firmware_update eeprom_config eeprom_refresh pi5_fan watchdog)
TASK_WAS_SKIPPED=0
TASK_SKIP_REASON=""

TASK_STATE_STATUS=""
TASK_STATE_TIMESTAMP=""
TASK_STATE_DESC=""

# Print command usage information.
usage() {
  cat <<USAGE
Usage: sudo ./$SCRIPT_NAME [options]

Options:
  --force                Re-run tasks even if already completed
  --dry-run              Print actions without changing the system
  --status               Show current optimisation status and exit
  --list-tasks           List available optimisation tasks and exit
  --skip <task>          Skip the named task (may be repeated)
  --only <task>          Run only the named task (may be repeated)
  --install-tailscale    Configure the Tailscale repository and install the package
  --install-docker       Configure Docker repository if possible and install Engine
  --locale <locale>      Set default system locale (e.g. en_US.UTF-8)
  --proxy-backend <val>  Configure nginx reverse proxy backend (use off/disable/disabled to remove)
  --install-zram         Enable compressed ZRAM swap configuration task
  --zram-algo <algo>     Override ZRAM compression algorithm (lz4|zstd|disabled)
  --overclock-conservative Enable CPU/GPU overclock profile (Pi 5/500 2.8 GHz, 4/400/3/Zero 2 firmware-safe)
  --secure-ssh           Harden sshd config and enable fail2ban protection
  --firmware-update      Run rpi-update non-interactively to install latest firmware
  --eeprom-update        Refresh Raspberry Pi bootloader EEPROM via rpi-eeprom-update
  --enable-watchdog      Enable hardware watchdog (dtparam=watchdog=on + systemd)
  --pi5-fan-profile      Apply a Pi 5 PWM fan curve (temps 50/60/67/75 C)
  --timezone <tz>        Set system timezone (e.g. Europe/London)
  --hostname <name>      Set system hostname
  --ssh-import-github <u> Append authorized_keys from https://github.com/<u>.keys
  --ssh-import-url <url> Append authorized_keys from a https://... URL
  --keep-screen-blanking Keep default desktop blanking behaviour
  --help                 Show this help message and exit
  --version              Print script version and exit

Tasks can be referenced by their short name shown with --list-tasks or --status.
USAGE
}

# Ensure log file exists and has correct permissions.
init_logging() {
  local log_dir
  log_dir=$(dirname "$LOG_FILE")
  if [[ ! -d "$log_dir" ]]; then
    mkdir -p "$log_dir"
  fi
  if [[ ! -f "$LOG_FILE" ]]; then
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
  fi
}

# Write a log message with level tag to stdout and log file.
log_with_level() {
  local level=$1
  shift
  local timestamp message
  timestamp=$(date +'%Y-%m-%d %H:%M:%S')
  message="$timestamp [$level] $*"
  if [[ "$level" == "ERROR" ]]; then
    echo "$message" >&2
  else
    echo "$message"
  fi
  echo "$message" >> "$LOG_FILE"
}

# Convenience wrapper for info-level logging.
log_info() {
  log_with_level INFO "$@"
}

# Convenience wrapper for warning-level logging.
log_warn() {
  log_with_level WARN "$@"
}

# Convenience wrapper for error-level logging.
log_error() {
  log_with_level ERROR "$@"
}

# Trap handler to log task failures with line numbers.
on_err() {
  local exit_code=$1
  local line_no=$2
  log_error "Failure (code=$exit_code) while running task '$CURRENT_TASK' at line $line_no"
}

# Abort execution unless running as root.
require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
  fi
}

# Create optimiser state directory and file if missing.
ensure_marker_store() {
  if [[ ! -d "$MARKER_DIR" ]]; then
    mkdir -p "$MARKER_DIR"
    chmod 755 "$MARKER_DIR"
  fi
  if [[ ! -f "$STATE_FILE" ]]; then
    touch "$STATE_FILE"
    chmod 644 "$STATE_FILE"
  fi
}

# Copy original file to timestamped backup once per run.
backup_file() {
  local path=$1
  if [[ ! -f "$path" ]]; then
    return
  fi
  if [[ -n ${BACKED_UP[$path]:-} ]]; then
    return
  fi
  local backup
  backup="${path}.pi-optimiser.$(date +%Y%m%d%H%M%S)"
  cp "$path" "$backup"
  BACKED_UP[$path]="$backup"
  log_info "Created backup $backup"
}

# Fetch dot-delimited key from JSON file using python helper.
read_json_field() {
  local file=$1
  local key=$2
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  python3 - "$file" "$key" <<'PY' || return 1
import json, sys
path, key = sys.argv[1:3]
try:
    with open(path) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(1)
value = data
for part in key.split('.'):
    if isinstance(value, dict) and part in value:
        value = value[part]
    else:
        sys.exit(1)
if value is None:
    sys.exit(1)
print(value)
PY
}

# Persist dot-delimited key/value pair to JSON, creating parents as needed.
write_json_field() {
  local file=$1
  local key=$2
  local value=$3
  python3 - "$file" "$key" "$value" <<'PY'
import json, os, sys
path, key, value = sys.argv[1:4]
os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
try:
    with open(path) as fh:
        data = json.load(fh)
except Exception:
    data = {}
ref = data
parts = key.split('.')
for part in parts[:-1]:
    ref = ref.setdefault(part, {})
ref[parts[-1]] = value
with open(path, 'w') as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write('\n')
PY
}

# Return previously configured proxy backend from state file.
get_stored_proxy_backend() {
  local backend
  if backend=$(read_json_field "$CONFIG_OPTIMISER_STATE" "proxy.backend" 2>/dev/null); then
    printf '%s\n' "$backend"
    return 0
  fi
  return 1
}

# Ensure a config.txt line exists exactly once (case-insensitive).
ensure_config_line() {
  local line=$1
  local target=${2:-$CONFIG_TXT_FILE}
  if [[ -z "$target" ]]; then
    target=$CONFIG_TXT_FILE
  fi
  if [[ ! -f "$target" ]]; then
    touch "$target"
  fi
  local result
  result=$(
    CONFIG_FILE="$target" CONFIG_LINE="$line" python3 <<'PY'
import os, sys
from pathlib import Path
config_path = Path(os.environ['CONFIG_FILE'])
line = os.environ['CONFIG_LINE'].strip()
try:
    existing = config_path.read_text().splitlines()
except FileNotFoundError:
    existing = []
out_lines = []
line_lower = line.lower()
changed = False
found = False
for raw in existing:
    stripped = raw.strip()
    candidate = stripped.lstrip('#').strip().lower()
    if candidate == line_lower:
        if not found:
            if stripped != line:
                changed = True
            out_lines.append(line)
            found = True
        else:
            changed = True
        continue
    out_lines.append(raw)
if not found:
    out_lines.append(line)
    changed = True
config_path.write_text('\n'.join(out_lines) + '\n')
print('changed' if changed else 'unchanged')
PY
  )
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    return 2
  fi
  if [[ $result == "changed" ]]; then
    return 0
  fi
  return 1
}

# Ensure config.txt contains exactly one `key=value` line for the given key.
# Replaces any previous value (commented or not) for the same key.
ensure_config_key_value() {
  local entry=$1
  local target=${2:-$CONFIG_TXT_FILE}
  if [[ -z "$target" ]]; then
    target=$CONFIG_TXT_FILE
  fi
  if [[ "$entry" != *=* ]]; then
    return 2
  fi
  if [[ ! -f "$target" ]]; then
    touch "$target"
  fi
  local key=${entry%%=*}
  local result
  result=$(
    CONFIG_FILE="$target" CONFIG_ENTRY="$entry" CONFIG_KEY="$key" python3 <<'PY'
import os
from pathlib import Path
config_path = Path(os.environ['CONFIG_FILE'])
entry = os.environ['CONFIG_ENTRY'].strip()
key = os.environ['CONFIG_KEY'].strip().lower()
try:
    existing = config_path.read_text().splitlines()
except FileNotFoundError:
    existing = []
out_lines = []
changed = False
found = False
for raw in existing:
    stripped = raw.strip()
    candidate = stripped.lstrip('#').strip()
    if '=' in candidate:
        cand_key = candidate.split('=', 1)[0].strip().lower()
        if cand_key == key:
            if not found:
                if stripped != entry:
                    changed = True
                out_lines.append(entry)
                found = True
            else:
                changed = True
            continue
    out_lines.append(raw)
if not found:
    out_lines.append(entry)
    changed = True
config_path.write_text('\n'.join(out_lines) + '\n')
print('changed' if changed else 'unchanged')
PY
  )
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    return 2
  fi
  if [[ $result == "changed" ]]; then
    return 0
  fi
  return 1
}

# Append line to a file if not already present.
ensure_line_in_file() {
  local file=$1
  local line=$2
  if [[ ! -f "$file" ]]; then
    touch "$file"
  fi
  if ! grep -Fx -- "$line" "$file" >/dev/null 2>&1; then
    echo "$line" >> "$file"
    return 0
  fi
  return 1
}


# Ensure sshd_config directive is set to the specified value.
update_sshd_config_option() {
  local key=$1
  local value=$2
  local file=${3:-/etc/ssh/sshd_config}
  local result
  result=$(
    SSHD_CONFIG="$file" SSHD_KEY="$key" SSHD_VALUE="$value" python3 <<'PY'
import os, sys
from pathlib import Path

path = Path(os.environ['SSHD_CONFIG'])
key = os.environ['SSHD_KEY']
key_lower = key.lower()
value = os.environ['SSHD_VALUE']

try:
    lines = path.read_text().splitlines()
except FileNotFoundError:
    lines = []

new_lines = []
found = False
changed = False

for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        new_lines.append(line)
        continue
    parts = stripped.split(None, 1)
    directive = parts[0].lower()
    if directive == key_lower:
        if not found:
            expected = f"{key} {value}"
            new_lines.append(expected)
            found = True
            if len(parts) == 1 or parts[1].strip() != value:
                changed = True
        else:
            changed = True
        continue
    new_lines.append(line)

if not found:
    new_lines.append(f"{key} {value}")
    changed = True

output = '\n'.join(new_lines) + '\n'
try:
    current = path.read_text()
except FileNotFoundError:
    current = ''
if current != output:
    path.write_text(output)
    print('changed')
else:
    print('unchanged')
PY
  )
  result=${result//$'\n'/}
  if [[ $result == "changed" ]]; then
    log_info "Updated ${key} in $file"
  else
    log_info "${key} already set in $file"
  fi
}


# Record task completion metadata to state file.
set_task_state() {
  local task=$1
  local status=$2
  local desc=$3
  ensure_marker_store
  local tmp
  tmp=$(mktemp)
  if [[ -f "$STATE_FILE" ]]; then
    awk -F'|' -v key="$task" '$1!=key' "$STATE_FILE" > "$tmp"
  fi
  printf '%s|%s|%s|%s\n' "$task" "$status" "$(date -Iseconds)" "$desc" >> "$tmp"
  mv "$tmp" "$STATE_FILE"
  chmod 644 "$STATE_FILE"
}

# Remove existing task entry from state file.
clear_task_state() {
  local task=$1
  if [[ ! -f "$STATE_FILE" ]]; then
    return
  fi
  local tmp
  tmp=$(mktemp)
  awk -F'|' -v key="$task" '$1!=key' "$STATE_FILE" > "$tmp"
  mv "$tmp" "$STATE_FILE"
  chmod 644 "$STATE_FILE"
}

# Populate global task state variables from state file entry.
get_task_state() {
  local task=$1
  if [[ ! -f "$STATE_FILE" ]]; then
    return 1
  fi
  local line
  line=$(awk -F'|' -v key="$task" '$1==key {print $0}' "$STATE_FILE")
  if [[ -z "$line" ]]; then
    return 1
  fi
  IFS='|' read -r _ TASK_STATE_STATUS TASK_STATE_TIMESTAMP TASK_STATE_DESC <<< "$line"
  return 0
}

# Return success when a task previously completed.
is_task_done() {
  if get_task_state "$1"; then
    [[ "$TASK_STATE_STATUS" == "completed" ]]
  else
    return 1
  fi
}

# Honour --skip/--only filters when deciding task execution.
should_run_task() {
  local task=$1
  if [[ -n ${SKIP_TASKS[$task]:-} ]]; then
    return 1
  fi
  if ((${#ONLY_TASKS[@]} > 0)); then
    local item
    for item in "${ONLY_TASKS[@]}"; do
      if [[ "$item" == "$task" ]]; then
        return 0
      fi
    done
    return 1
  fi
  return 0
}

# Guard tasks for idempotent execution with state tracking.
apply_once() {
  local task=$1
  local desc=$2
  local func=$3
  shift 3
  CURRENT_TASK="$task"
  TASK_WAS_SKIPPED=0
  TASK_SKIP_REASON=""
  if [[ $FORCE -eq 0 ]] && is_task_done "$task"; then
    log_info "Skipping $task (already completed)"
    SUMMARY_SKIPPED+=("$task (already completed)")
    return 0
  fi
  if [[ $FORCE -eq 1 ]]; then
    clear_task_state "$task"
  fi
  log_info "Running task $task: $desc"
  if [[ $DRY_RUN -eq 1 ]]; then
    log_info "[dry-run] $task not executed"
    SUMMARY_SKIPPED+=("$task (dry-run)")
    return 0
  fi
  if "$func" "$@"; then
    if [[ ${TASK_WAS_SKIPPED:-0} -eq 1 ]]; then
      local reason=${TASK_SKIP_REASON:-"$task (task skipped)"}
      SUMMARY_SKIPPED+=("$reason")
    else
      set_task_state "$task" "completed" "$desc"
      log_info "Completed task $task"
      SUMMARY_COMPLETED+=("$task")
    fi
  else
    set_task_state "$task" "failed" "$desc"
    log_error "Task $task failed"
    SUMMARY_FAILED+=("$task")
    return 1
  fi
}

# Show current task status table.
print_status() {
  ensure_marker_store
  printf '%-18s %-12s %-25s %s\n' "TASK" "STATUS" "TIMESTAMP" "DETAILS"
  printf '%-18s %-12s %-25s %s\n' "----" "------" "---------" "-------"
  local entry task func desc status timestamp details
  for entry in "${TASK_DEFS[@]}"; do
    IFS=: read -r task func desc <<< "$entry"
    if get_task_state "$task"; then
      status="$TASK_STATE_STATUS"
      timestamp="$TASK_STATE_TIMESTAMP"
      details="$TASK_STATE_DESC"
    else
      status="pending"
      timestamp="--"
      details="$desc"
    fi
    printf '%-18s %-12s %-25s %s\n' "$task" "$status" "$timestamp" "$details"
  done
}

# Emit post-run summary across completed/skipped/failed tasks.
print_run_summary() {
  echo
  log_info "Run summary:"
  local item
  if ((${#SUMMARY_COMPLETED[@]} > 0)); then
    for item in "${SUMMARY_COMPLETED[@]}"; do
      log_info "  completed: $item"
    done
  else
    log_info "  completed: none"
  fi
  if ((${#SUMMARY_SKIPPED[@]} > 0)); then
    for item in "${SUMMARY_SKIPPED[@]}"; do
      log_info "  skipped: $item"
    done
  else
    log_info "  skipped: none"
  fi
  if ((${#SUMMARY_FAILED[@]} > 0)); then
    for item in "${SUMMARY_FAILED[@]}"; do
      log_warn "  failed: $item"
    done
  fi
  if ((${#PRECHECK_BLOCKERS[@]} > 0)); then
    log_warn "  preflight blockers: ${PRECHECK_BLOCKERS[*]}"
  fi
  if ((${#PRECHECK_WARNINGS[@]} > 0)); then
    log_warn "  preflight warnings: ${PRECHECK_WARNINGS[*]}"
  fi
}

# List all available tasks with descriptions.
list_tasks() {
  printf '%-18s %s\n' "TASK" "DESCRIPTION"
  printf '%-18s %s\n' "----" "-----------"
  local entry task func desc
  for entry in "${TASK_DEFS[@]}"; do
    IFS=: read -r task func desc <<< "$entry"
    printf '%-18s %s\n' "$task" "$desc"
  done
  echo
  echo "Use --install-tailscale, --install-docker, or --proxy-backend to enable optional tasks."
}

# Parse CLI arguments and populate global flags.
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force)
        FORCE=1
        ;;
      --dry-run)
        DRY_RUN=1
        ;;
      --status)
        STATUS_ONLY=1
        ;;
      --list-tasks)
        LIST_TASKS=1
        ;;
      --skip)
        if [[ $# -lt 2 ]]; then
          echo "--skip requires a task name" >&2
          exit 1
        fi
        SKIP_TASKS[$2]=1
        shift
        ;;
      --only)
        if [[ $# -lt 2 ]]; then
          echo "--only requires a task name" >&2
          exit 1
        fi
        ONLY_TASKS+=("$2")
        shift
        ;;
      --install-tailscale)
        INSTALL_TAILSCALE=1
        ;;
      --install-docker)
        INSTALL_DOCKER=1
        ;;
      --locale)
        if [[ $# -lt 2 ]]; then
          echo "--locale requires a locale value" >&2
          exit 1
        fi
        REQUESTED_LOCALE=$2
        shift
        ;;
      --install-zram)
        INSTALL_ZRAM=1
        ;;
      --proxy-backend)
        if [[ $# -lt 2 ]]; then
          echo "--proxy-backend requires a value" >&2
          exit 1
        fi
        PROXY_BACKEND=$2
        shift
        ;;
      --zram-algo)
        if [[ $# -lt 2 ]]; then
          echo "--zram-algo requires an algorithm name" >&2
          exit 1
        fi
        local algo_override=${2,,}
        case "$algo_override" in
          lz4|zstd|disabled)
            ZRAM_ALGO_OVERRIDE=$algo_override
            ;;
          *)
            echo "Unsupported --zram-algo value: $2 (allowed: lz4, zstd, disabled)" >&2
            exit 1
            ;;
        esac
        shift
        ;;
      --overclock-conservative)
        REQUEST_OC_CONSERVATIVE=1
        ;;
      --secure-ssh)
        SECURE_SSH=1
        ;;
      --firmware-update)
        FIRMWARE_UPDATE=1
        ;;
      --eeprom-update)
        EEPROM_UPDATE=1
        ;;
      --enable-watchdog)
        INSTALL_WATCHDOG=1
        ;;
      --pi5-fan-profile)
        INSTALL_PI5_FAN_PROFILE=1
        ;;
      --timezone)
        if [[ $# -lt 2 ]]; then
          echo "--timezone requires a zone name" >&2
          exit 1
        fi
        REQUESTED_TIMEZONE=$2
        shift
        ;;
      --hostname)
        if [[ $# -lt 2 ]]; then
          echo "--hostname requires a name" >&2
          exit 1
        fi
        REQUESTED_HOSTNAME=$2
        shift
        ;;
      --ssh-import-github)
        if [[ $# -lt 2 ]]; then
          echo "--ssh-import-github requires a GitHub username" >&2
          exit 1
        fi
        SSH_IMPORT_GITHUB=$2
        shift
        ;;
      --ssh-import-url)
        if [[ $# -lt 2 ]]; then
          echo "--ssh-import-url requires a URL" >&2
          exit 1
        fi
        SSH_IMPORT_URL=$2
        shift
        ;;
      --keep-screen-blanking)
        KEEP_SCREEN_BLANKING=1
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      --version)
        echo "$SCRIPT_NAME $SCRIPT_VERSION"
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage
        exit 1
        ;;
    esac
    shift
  done
}

# Populate OS identification fields from /etc/os-release.
load_os_release() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID=${ID:-raspbian}
    OS_CODENAME=${VERSION_CODENAME:-bookworm}
    OS_ID_LIKE=${ID_LIKE:-debian}
  else
    OS_ID="raspbian"
    OS_CODENAME="bookworm"
    OS_ID_LIKE="debian"
  fi
}

# Infer root filesystem backing device type for logging/gating.
detect_boot_device() {
  local root_source
  root_source=$(findmnt -no SOURCE / 2>/dev/null || true)
  if [[ -z "$root_source" ]]; then
    SYSTEM_BOOT_DEVICE="unknown"
    return
  fi
  case "$root_source" in
    /dev/mmcblk*)
      SYSTEM_BOOT_DEVICE="sdcard"
      ;;
    /dev/sd*)
      SYSTEM_BOOT_DEVICE="usb"
      ;;
    /dev/nvme*)
      SYSTEM_BOOT_DEVICE="nvme"
      ;;
    PARTUUID=*)
      # Resolve via blkid when PARTUUID is used
      local partuuid resolved
      partuuid=${root_source#PARTUUID=}
      resolved=$(blkid -t "PARTUUID=$partuuid" -o device 2>/dev/null | head -n1 || true)
      if [[ -n "$resolved" ]]; then
        root_source="$resolved"
        case "$root_source" in
          /dev/mmcblk*) SYSTEM_BOOT_DEVICE="sdcard" ;;
          /dev/sd*) SYSTEM_BOOT_DEVICE="usb" ;;
          /dev/nvme*) SYSTEM_BOOT_DEVICE="nvme" ;;
          *) SYSTEM_BOOT_DEVICE="$root_source" ;;
        esac
      else
        SYSTEM_BOOT_DEVICE="partuuid:$partuuid"
      fi
      ;;
    *)
      SYSTEM_BOOT_DEVICE="$root_source"
      ;;
  esac
}

# Resolve the firmware config.txt / cmdline.txt paths, falling back to the
# pre-Bookworm /boot/* locations when /boot/firmware/ isn't mounted.
detect_boot_paths() {
  if [[ ! -f /boot/firmware/config.txt && -f /boot/config.txt ]]; then
    CONFIG_TXT_FILE=/boot/config.txt
  fi
  if [[ ! -f /boot/firmware/cmdline.txt && -f /boot/cmdline.txt ]]; then
    CMDLINE_FILE=/boot/cmdline.txt
  fi
}

# Collect model, RAM, kernel, firmware, and boot medium details.
gather_system_info() {
  detect_boot_paths
  if [[ -r /proc/device-tree/model ]]; then
    SYSTEM_MODEL=$(tr -d '\0' </proc/device-tree/model | tr -d '\n' || true)
  fi
  if [[ -z "$SYSTEM_MODEL" ]]; then
    SYSTEM_MODEL=$(uname -m)
  fi

  if [[ $SYSTEM_MODEL == *"Raspberry Pi 5"* || $SYSTEM_MODEL == *"Raspberry Pi 500"* ]]; then
    SYSTEM_PI_GEN="5"
  elif [[ $SYSTEM_MODEL == *"Raspberry Pi 4"* || $SYSTEM_MODEL == *"Raspberry Pi 400"* ]]; then
    SYSTEM_PI_GEN="4"
  elif [[ $SYSTEM_MODEL == *"Raspberry Pi 3"* ]]; then
    SYSTEM_PI_GEN="3"
  elif [[ $SYSTEM_MODEL == *"Raspberry Pi Zero 2"* ]]; then
    SYSTEM_PI_GEN="zero2"
  elif [[ $SYSTEM_MODEL == *"Raspberry Pi"* ]]; then
    SYSTEM_PI_GEN="other"
  else
    SYSTEM_PI_GEN="unknown"
  fi

  local mem_kb
  if mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null); then
    SYSTEM_RAM_MB=$((mem_kb / 1024))
  fi

  SYSTEM_KERNEL=$(uname -r)
  if [[ -r /proc/device-tree/chosen/firmware/revision ]]; then
    SYSTEM_FIRMWARE=$(tr -d '\0' </proc/device-tree/chosen/firmware/revision | tr -d '\n' || true)
  fi
  if [[ -z "$SYSTEM_FIRMWARE" && -r /proc/cpuinfo ]]; then
    SYSTEM_FIRMWARE=$(awk -F': ' '/^Revision/ {print $2}' /proc/cpuinfo | head -n1)
  fi
  detect_boot_device

  log_info "Detected hardware model: ${SYSTEM_MODEL:-unknown} (Pi generation: ${SYSTEM_PI_GEN:-unknown}, RAM: ${SYSTEM_RAM_MB} MB)"
  log_info "Kernel: ${SYSTEM_KERNEL:-unknown}; Firmware: ${SYSTEM_FIRMWARE:-unknown}"
  if [[ -n "$SYSTEM_BOOT_DEVICE" ]]; then
    log_info "Root filesystem appears to run from: $SYSTEM_BOOT_DEVICE"
  fi
}

# Convenience helper to compare detected Pi generation.
pi_is_generation() {
  local target=$1
  [[ ${SYSTEM_PI_GEN:-unknown} == "$target" ]]
}

# Determine if display KMS tweaks are applicable (Pi 4/5).
pi_supports_kms_overlays() {
  case ${SYSTEM_PI_GEN:-unknown} in
    4|5)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

# Return success when task should be skipped under power/thermal blockers.
is_power_sensitive_task() {
  local candidate=$1
  local task
  for task in "${POWER_SENSITIVE_TASKS[@]}"; do
    if [[ "$task" == "$candidate" ]]; then
      return 0
    fi
  done
  return 1
}

# Translate vcgencmd throttle bitmask into readable text.
describe_throttle_bits() {
  local value=$1
  local -a messages=()
  ((value & 0x1)) && messages+=("under-voltage (present)")
  ((value & 0x2)) && messages+=("arm frequency capped (present)")
  ((value & 0x4)) && messages+=("currently throttled")
  ((value & 0x8)) && messages+=("soft temp limit (present)")
  ((value & 0x10000)) && messages+=("under-voltage occurred")
  ((value & 0x20000)) && messages+=("frequency capping occurred")
  ((value & 0x40000)) && messages+=("throttle occurred")
  ((value & 0x80000)) && messages+=("soft temp limit occurred")
  if ((${#messages[@]} == 0)); then
    echo "no throttle flags set"
  else
    printf '%s' "${messages[*]}"
  fi
}

# Run power, thermal, disk, and connectivity checks before tasks.
preflight_checks() {
  PRECHECK_WARNINGS=()
  PRECHECK_BLOCKERS=()
  POWER_HEALTHY=1
  NETWORK_AVAILABLE=1

  log_info "Running preflight checks"

  if command -v vcgencmd >/dev/null 2>&1; then
    local throttled_raw throttled_hex throttled_val temp_raw temp_c
    throttled_raw=$(vcgencmd get_throttled 2>/dev/null || true)
    if [[ $throttled_raw =~ (0x[0-9a-fA-F]+) ]]; then
      throttled_hex=${BASH_REMATCH[1]}
      throttled_val=$((16#${throttled_hex#0x}))
      local description
      description=$(describe_throttle_bits "$throttled_val")
      if ((throttled_val == 0)); then
        log_info "  Power/Thermal: OK (throttled=$throttled_hex)"
      else
        log_warn "  Power/Thermal: throttled flag $throttled_hex -> $description"
        if ((throttled_val & 0x1)) || ((throttled_val & 0x4)) || ((throttled_val & 0x8)); then
          POWER_HEALTHY=0
          PRECHECK_BLOCKERS+=("Power or thermal issue detected (throttled=$throttled_hex)")
        else
          PRECHECK_WARNINGS+=("Historical throttle detected (throttled=$throttled_hex)")
        fi
      fi
    else
      PRECHECK_WARNINGS+=("Unable to parse vcgencmd get_throttled output: $throttled_raw")
    fi

    temp_raw=$(vcgencmd measure_temp 2>/dev/null || true)
    if [[ $temp_raw =~ =([0-9.]+) ]]; then
      temp_c=${BASH_REMATCH[1]}
      log_info "  Reported SoC temperature: ${temp_c}°C"
      if (( ${temp_c%.*} >= 80 )); then
        PRECHECK_WARNINGS+=("SoC temperature ${temp_c}°C is near throttle range")
      fi
    fi
  else
    PRECHECK_WARNINGS+=("vcgencmd not available; skipping power/thermal checks")
  fi

  local free_mb
  if free_mb=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}'); then
    if (( free_mb < 512 )); then
      PRECHECK_WARNINGS+=("Root filesystem low on space (${free_mb}MB available)")
    fi
  fi

  # Simple connectivity probe to inform apt operations
  if command -v ping >/dev/null 2>&1; then
    if ! ping -c1 -W2 8.8.8.8 >/dev/null 2>&1 && ! ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
      NETWORK_AVAILABLE=0
      PRECHECK_WARNINGS+=("Network connectivity test failed; apt operations may fail")
    fi
  fi

  if ((${#PRECHECK_BLOCKERS[@]} > 0)); then
    local item
    for item in "${PRECHECK_BLOCKERS[@]}"; do
      log_warn "  Blocker: $item"
    done
  else
    log_info "  Blockers: none"
  fi

  if ((${#PRECHECK_WARNINGS[@]} > 0)); then
    local warn
    for warn in "${PRECHECK_WARNINGS[@]}"; do
      log_warn "  Warning: $warn"
    done
  else
    log_info "  Warnings: none"
  fi
}

# Compute ZRAM size based on RAM tier with sensible caps.
determine_zram_target_mb() {
  local ram_mb=${SYSTEM_RAM_MB:-0}
  if (( ram_mb <= 0 )); then
    echo 0
    return
  fi
  local target
  if (( ram_mb <= 2048 )); then
    target=$((ram_mb * 75 / 100))
  elif (( ram_mb <= 4096 )); then
    target=$((ram_mb * 50 / 100))
  elif (( ram_mb <= 8192 )); then
    target=$((ram_mb * 30 / 100))
  else
    target=$((ram_mb * 25 / 100))
  fi
  if (( target < 256 )); then
    target=256
  fi
  local max=$((ram_mb / 2))
  if (( max < 256 )); then
    max=256
  fi
  if (( target > max )); then
    target=$max
  fi
  echo "$target"
}

# Perform apt-get update at most once per run.
# Swallows failures and logs a warning; callers proceed with cached package lists.
apt_update_once() {
  if [[ $APT_UPDATED -eq 0 ]]; then
    if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
      log_warn "Network connectivity previously reported as unavailable; attempting apt-get update regardless"
    fi
    local rc=0
    DEBIAN_FRONTEND=noninteractive apt-get update || rc=$?
    if [[ $rc -eq 0 ]]; then
      APT_UPDATED=1
    else
      log_warn "apt-get update failed (rc=$rc); proceeding with cached package lists"
    fi
  fi
  return 0
}

# Install missing packages via apt-get when required.
ensure_packages() {
  local -a missing=()
  local pkg
  for pkg in "$@"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if ((${#missing[@]} == 0)); then
    return 0
  fi
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Proceeding with package installation despite failed connectivity check"
  fi
  apt_update_once
  log_info "Installing packages: ${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

# Check whether a systemd unit definition exists.
unit_exists() {
  systemctl list-unit-files "$1" >/dev/null 2>&1
}

# Disable and stop a systemd unit if present.
unit_disable_now() {
  local unit=$1
  if ! unit_exists "$unit"; then
    return
  fi
  if ! systemctl disable --now "$unit" >/dev/null 2>&1; then
    log_warn "Unable to disable $unit"
  else
    log_info "Disabled $unit"
  fi
}

# Mask a systemd unit to prevent activation.
unit_mask() {
  local unit=$1
  if ! unit_exists "$unit"; then
    return
  fi
  if ! systemctl mask "$unit" >/dev/null 2>&1; then
    log_warn "Unable to mask $unit"
  else
    log_info "Masked $unit"
  fi
}

# Attempt to remount a path to apply updated options.
remount_path() {
  local path=$1
  if mountpoint -q "$path"; then
    if ! mount -o remount "$path" >/dev/null 2>&1; then
      mount "$path" >/dev/null 2>&1 || true
    fi
  fi
}

# Purge optional desktop software and clean apt caches.
task_remove_bloat_packages() {
  local -a patterns=(
    'bluej'
    'claws-mail'
    'code-the-classics'*
    'geany'
    'greenfoot'
    'libreoffice-*'
    'minecraft-pi'
    'nodered'
    'nuscratch'
    'python-games'
    'raspberrypi-connect'
    'rpi-connect'
    'rpi-connect-server'
    'scratch'
    'scratch2'
    'scratch3'
    'sense-hat'
    'smartsim'
    'sonic-pi'
    'thonny'
    'wolfram-engine'
  )
  declare -A unique_packages=()
  local pattern pkg
  for pattern in "${patterns[@]}"; do
    while IFS= read -r pkg; do
      [[ -n "$pkg" ]] || continue
      unique_packages[$pkg]=1
    done < <(dpkg-query -W -f='${Package}\n' "$pattern" 2>/dev/null || true)
  done
  local -a to_remove=()
  for pkg in "${!unique_packages[@]}"; do
    to_remove+=("$pkg")
  done
  if ((${#to_remove[@]} == 0)); then
    log_info "No optional desktop packages detected"
    return 0
  fi
  log_info "Purging packages: ${to_remove[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get purge -y "${to_remove[@]}"
  DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
  DEBIAN_FRONTEND=noninteractive apt-get clean
}

# Apply noatime and commit adjustments to root filesystem entry.
task_tune_fstab() {
  if grep -E "^[[:space:]]*[^#[:space:]]+[[:space:]]+/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]*noatime" /etc/fstab >/dev/null; then
    log_info "Root filesystem already has noatime configured"
  else
    backup_file /etc/fstab
    python3 <<'PY'
from pathlib import Path
path = Path('/etc/fstab')
lines = path.read_text().splitlines()
updated_lines = []
changed = False
for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        updated_lines.append(line)
        continue
    parts = line.split()
    if len(parts) >= 4 and parts[1] == '/':
        opts = parts[3].split(',')
        ordered = []
        seen = set()
        for opt in opts:
            if opt and opt not in seen:
                ordered.append(opt)
                seen.add(opt)
        desired = ['noatime', 'commit=60', 'errors=remount-ro']
        for opt in desired:
            if opt not in seen:
                ordered.append(opt)
                seen.add(opt)
                changed = True
        parts[3] = ','.join(ordered)
        line = "\t".join(parts[:4])
        if len(parts) > 4:
            line = line + "\t" + "\t".join(parts[4:])
    updated_lines.append(line)
if changed:
    path.write_text("\n".join(updated_lines) + "\n")
PY
    log_info "Applied noatime and commit=60 to root filesystem"
    remount_path /
  fi
}

# Disable legacy swapfile service and ensure swap is off.
task_disable_swap() {
  local result=0
  if command -v dphys-swapfile >/dev/null 2>&1; then
    if ! dphys-swapfile swapoff >/dev/null 2>&1; then
      log_warn "dphys-swapfile swapoff reported an issue"
      result=1
    else
      log_info "Disabled swap via dphys-swapfile"
    fi
  fi
  if unit_exists dphys-swapfile.service; then
    if ! systemctl disable --now dphys-swapfile.service >/dev/null 2>&1; then
      log_warn "Unable to disable dphys-swapfile.service"
      result=1
    else
      log_info "Disabled dphys-swapfile.service"
    fi
  fi
  if [[ -f /etc/dphys-swapfile ]]; then
    sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=0/' /etc/dphys-swapfile
  fi
  swapoff -a >/dev/null 2>&1 || true
  return $result
}

# Select preferred ZRAM compression algorithm (default lz4).
pick_zram_algorithm() {
  if [[ -n "$ZRAM_ALGO_OVERRIDE" ]]; then
    echo "$ZRAM_ALGO_OVERRIDE"
    return
  fi
  echo "lz4"
}

# Configure or disable systemd zram generator with sized swap device.
task_configure_zram() {
  if [[ $ZRAM_ALGO_OVERRIDE == "disabled" ]]; then
    local removed=0
    if [[ -f "$ZRAM_CONF_FILE" ]]; then
      backup_file "$ZRAM_CONF_FILE"
      rm -f "$ZRAM_CONF_FILE"
      removed=1
    fi
    if systemctl list-unit-files systemd-zram-setup@.service >/dev/null 2>&1; then
      systemctl disable --now systemd-zram-setup@zram0 >/dev/null 2>&1 || log_warn "Unable to disable systemd-zram-setup@zram0"
    fi
    swapoff /dev/zram0 >/dev/null 2>&1 || true
    write_json_field "$CONFIG_OPTIMISER_STATE" "zram.size_mb" "disabled"
    write_json_field "$CONFIG_OPTIMISER_STATE" "zram.algorithm" "disabled"
    write_json_field "$CONFIG_OPTIMISER_STATE" "zram.last_configured" "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
    if (( removed == 1 )); then
      log_info "Disabled ZRAM and removed $ZRAM_CONF_FILE"
    else
      log_info "ZRAM already disabled"
    fi
    return 0
  fi

  if [[ $INSTALL_ZRAM -eq 0 ]]; then
    log_info "ZRAM not requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi

  local size_mb algo
  size_mb=$(determine_zram_target_mb)
  if (( size_mb <= 0 )); then
    log_warn "Unable to determine a suitable ZRAM size; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (no RAM info)"
    return 0
  fi

  algo=$(pick_zram_algorithm)
  if [[ $algo == "disabled" ]]; then
    log_warn "ZRAM algorithm set to disabled; skipping configuration"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (algorithm disabled)"
    return 0
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    log_info "[dry-run] Would configure systemd zram generator for ${size_mb}MB swap (algo $algo)"
    return 0
  fi

  ensure_packages systemd-zram-generator

  mkdir -p "$(dirname "$ZRAM_CONF_FILE")"
  if [[ -f "$ZRAM_CONF_FILE" ]]; then
    backup_file "$ZRAM_CONF_FILE"
  fi

  if [[ -n "$ZRAM_ALGO_OVERRIDE" ]]; then
    log_info "Using user-specified ZRAM compression algorithm: $algo"
  else
    log_info "Selected ZRAM compression algorithm: $algo"
  fi

  cat <<CFG > "$ZRAM_CONF_FILE"
[zram0]
zram-size = ${size_mb}M
compression-algorithm = $algo
swap-priority = 100
CFG

  log_info "Configured $ZRAM_CONF_FILE for ${size_mb}MB ZRAM swap"
  systemctl daemon-reload >/dev/null 2>&1 || true
  if systemctl list-unit-files systemd-zram-setup@.service >/dev/null 2>&1; then
    systemctl enable --now systemd-zram-setup@zram0 >/dev/null 2>&1 || log_warn "Unable to enable systemd-zram-setup@zram0"
  else
    log_warn "systemd-zram-setup@.service not found; ensure systemd-zram-generator is installed"
  fi

  write_json_field "$CONFIG_OPTIMISER_STATE" "zram.size_mb" "$size_mb"
  write_json_field "$CONFIG_OPTIMISER_STATE" "zram.algorithm" "$algo"
  write_json_field "$CONFIG_OPTIMISER_STATE" "zram.last_configured" "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"

  if command -v zramctl >/dev/null 2>&1; then
    local zram_status
    zram_status=$(zramctl 2>/dev/null | sed 's/^/    /')
    if [[ -n "$zram_status" ]]; then
      log_info "Current zramctl status:\n$zram_status"
    fi
  fi
  if command -v swapon >/dev/null 2>&1; then
    local swap_status
    swap_status=$(swapon --show 2>/dev/null | sed 's/^/    /')
    if [[ -n "$swap_status" ]]; then
      log_info "Active swap devices:\n$swap_status"
    fi
  fi
}

# Keep systemd journal in RAM with modest size limits.
task_configure_journald() {
  mkdir -p "$(dirname "$JOURNALD_CONF_FILE")"
  cat <<'CFG' > "$JOURNALD_CONF_FILE"
[Journal]
Storage=volatile
RuntimeMaxUse=50M
SystemMaxUse=50M
MaxRetentionSec=1week
CFG
  systemctl restart systemd-journald >/dev/null 2>&1 || log_warn "systemd-journald restart failed"
}

# Apply kernel tuning for memory, file limits, and networking.
task_configure_sysctl() {
  cat <<'CFG' > "$SYSCTL_CONF_FILE"
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_writeback_centisecs = 6000
vm.dirty_expire_centisecs = 12000
fs.inotify.max_user_watches = 524288
fs.file-max = 2097152
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.netdev_max_backlog = 4096
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
CFG
  sysctl -p "$SYSCTL_CONF_FILE" >/dev/null 2>&1 || log_warn "sysctl reload encountered an issue"
}

# Harden apt behaviour and disable automatic background jobs.
task_configure_apt() {
  cat <<'CFG' > "$APT_CONF_FILE"
APT::Install-Recommends "0";
APT::Install-Suggests "0";
APT::Get::AutomaticRemove "1";
APT::Periodic::Enable "0";
Binary::apt::APT::Keep-Downloaded-Packages "false";
Acquire::Languages "none";
CFG
  unit_disable_now apt-daily.timer
  unit_disable_now apt-daily-upgrade.timer
  unit_mask apt-daily.service
  unit_mask apt-daily-upgrade.service
  DEBIAN_FRONTEND=noninteractive apt-get clean
}


# Configure security-only unattended upgrades on a timer.
task_configure_unattended_upgrades() {
  load_os_release
  ensure_packages unattended-upgrades
  local os_origin=${OS_ID^}
  local codename=$OS_CODENAME
  local uu_bin
  uu_bin=$(command -v unattended-upgrade || true)
  if [[ -z "$uu_bin" ]]; then
    if [[ -x /usr/bin/unattended-upgrade ]]; then
      uu_bin=/usr/bin/unattended-upgrade
    elif [[ -x /usr/sbin/unattended-upgrade ]]; then
      uu_bin=/usr/sbin/unattended-upgrade
    else
      log_warn "unattended-upgrade binary not found; skipping timer setup"
      TASK_WAS_SKIPPED=1
      TASK_SKIP_REASON="$CURRENT_TASK (unattended-upgrade binary missing)"
      return 0
    fi
  fi
  cat <<CFG > "$UNATTENDED_CONF_FILE"
Unattended-Upgrade::Origins-Pattern {
        "origin=${os_origin},codename=${codename}-security";
        "origin=Debian,codename=${codename}-security";
        "origin=Raspberry Pi Foundation,codename=${codename}";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
CFG
  cat <<CFG > "$UNATTENDED_SERVICE"
[Unit]
Description=Run unattended-upgrades (pi-optimiser)
Documentation=man:unattended-upgrade(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${uu_bin} --quiet
SuccessExitStatus=0 2
CFG
  cat <<'CFG' > "$UNATTENDED_TIMER"
[Unit]
Description=Run unattended-upgrades every 6 hours (pi-optimiser)
Documentation=man:unattended-upgrade(8)

[Timer]
OnBootSec=20min
OnUnitActiveSec=6h
AccuracySec=5min
Persistent=true

[Install]
WantedBy=timers.target
CFG
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now pi-unattended-upgrades.timer >/dev/null 2>&1 || log_warn "Could not enable pi-unattended-upgrades.timer"
}

# Ensure essential command-line utilities are installed.
task_install_cli_tools() {
  local -a packages=(
    htop
    iftop
    iotop
    locales-all
    pigz
    screen
    tmux
  )
  local -a missing=()
  local pkg
  for pkg in "${packages[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if ((${#missing[@]} == 0)); then
    log_info "Essential CLI tools already installed"
    return 0
  fi
  ensure_packages "${missing[@]}"
}

# Set system locale when requested via --locale flag.
task_configure_locale() {
  if [[ -z "$REQUESTED_LOCALE" ]]; then
    log_info "No locale requested; skipping locale configuration"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  ensure_packages locales-all
  if [[ -f /etc/default/locale ]]; then
    backup_file /etc/default/locale
  fi
  cat <<EOF > /etc/default/locale
LANG=$REQUESTED_LOCALE
LC_ALL=$REQUESTED_LOCALE
EOF
  if update-locale LANG="$REQUESTED_LOCALE" LC_ALL="$REQUESTED_LOCALE" >/dev/null 2>&1; then
    log_info "Configured system locale to $REQUESTED_LOCALE"
  else
    log_warn "update-locale reported issues while setting $REQUESTED_LOCALE"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "locale.lang" "$REQUESTED_LOCALE"
}



# Manage nginx reverse proxy configuration and lifecycle.
task_configure_proxy() {
  if [[ -z "$PROXY_BACKEND" ]]; then
    log_info "Proxy support not requested; skipping proxy configuration"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi

  local backend_lower=${PROXY_BACKEND,,}
  local conf=/etc/nginx/sites-available/pi-optimiser-proxy
  local enabled=/etc/nginx/sites-enabled/pi-optimiser-proxy

  if [[ $backend_lower == "off" || $backend_lower == "false" || $backend_lower == "disable" || $backend_lower == "disabled" || $backend_lower == "null" || $backend_lower == "none" ]]; then
    rm -f "$enabled"
    if [[ -f "$conf" ]]; then
      backup_file "$conf"
      rm -f "$conf"
    fi
    if systemctl list-unit-files nginx.service >/dev/null 2>&1; then
      systemctl stop nginx >/dev/null 2>&1 || true
      systemctl disable nginx >/dev/null 2>&1 || log_warn "Unable to disable nginx service"
    fi
    log_info "Proxy configuration removed; nginx disabled"
    write_json_field "$CONFIG_OPTIMISER_STATE" "proxy.backend" "disabled"
    return 0
  fi

  ensure_packages nginx-light
  mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
  if [[ -f "$conf" ]]; then
    backup_file "$conf"
  fi
  cat <<EOF > "$conf"

map \$http_upgrade \$connection_upgrade {
    default Upgrade;
    ''      close;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location / {
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;

        # WebSocket support (harmless for normal HTTP)
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Sec-WebSocket-Key \$http_sec_websocket_key;
        proxy_set_header Sec-WebSocket-Version \$http_sec_websocket_version;
        proxy_set_header Sec-WebSocket-Protocol \$http_sec_websocket_protocol;
        proxy_set_header Sec-WebSocket-Extensions \$http_sec_websocket_extensions;
        proxy_cache_bypass \$http_upgrade;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_connect_timeout 60;

        proxy_pass $PROXY_BACKEND;
    }
}
EOF
  local default_link=/etc/nginx/sites-enabled/default
  local default_target=""
  if [[ -L "$default_link" ]]; then
    default_target=$(readlink "$default_link")
  elif [[ -f "$default_link" ]]; then
    default_target="$default_link"
  fi

  ln -sf "$conf" "$enabled"
  rm -f "$default_link"

  if ! nginx -t >/dev/null 2>&1; then
    log_warn "nginx configuration test failed; reverting proxy site"
    rm -f "$enabled"
    if [[ -n "$default_target" ]]; then
      ln -sf "$default_target" "$default_link" 2>/dev/null || true
    fi
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (nginx config failed validation)"
    return 0
  fi

  systemctl enable --now nginx >/dev/null 2>&1 || log_warn "Unable to enable nginx service"
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || log_warn "Unable to reload nginx"
  write_json_field "$CONFIG_OPTIMISER_STATE" "proxy.backend" "$PROXY_BACKEND"
  log_info "Proxy configured to $PROXY_BACKEND"
}
# Raise system and user ulimit defaults for file descriptors/processes.
task_configure_limits() {
  local limits_dir system_dir user_dir
  limits_dir=$(dirname "$LIMITS_CONF_FILE")
  mkdir -p "$limits_dir"
  cat <<'CFG' > "$LIMITS_CONF_FILE"
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
* soft nproc 32768
* hard nproc 32768
root soft nproc 32768
root hard nproc 32768
CFG
  log_info "Configured $LIMITS_CONF_FILE"

  system_dir=$(dirname "$SYSTEMD_SYSTEM_LIMITS")
  mkdir -p "$system_dir"
  cat <<'CFG' > "$SYSTEMD_SYSTEM_LIMITS"
[Manager]
DefaultLimitNOFILE=65535
DefaultLimitNPROC=32768
CFG
  log_info "Configured $SYSTEMD_SYSTEM_LIMITS"

  user_dir=$(dirname "$SYSTEMD_USER_LIMITS")
  mkdir -p "$user_dir"
  cat <<'CFG' > "$SYSTEMD_USER_LIMITS"
[Manager]
DefaultLimitNOFILE=65535
DefaultLimitNPROC=32768
CFG
  log_info "Configured $SYSTEMD_USER_LIMITS"

  systemctl daemon-reload >/dev/null 2>&1 || true
  if unit_exists systemd-logind.service; then
    systemctl restart systemd-logind >/dev/null 2>&1 || log_warn "systemd-logind restart encountered an issue"
  fi
}

# Disable non-essential background services for kiosk workloads.
task_disable_services() {
  local -a units=(
    triggerhappy.service
    bluetooth.service
    hciuart.service
    avahi-daemon.service
    cups.service
    rsyslog.service
  )
  local unit
  for unit in "${units[@]}"; do
    if unit_exists "$unit"; then
      unit_disable_now "$unit"
    fi
  done
}

# Configure Tailscale repository and install client when requested.
task_setup_tailscale() {
  load_os_release
  ensure_packages ca-certificates curl gnupg
  local repo_id repo_suite key_dir list_dir key_url
  repo_id=$OS_ID
  if [[ $repo_id == "raspbian" || $repo_id == "debian" ]]; then
    repo_id="debian"
  elif [[ $repo_id == "ubuntu" || $repo_id == "pop" ]]; then
    repo_id="ubuntu"
  elif [[ -n $OS_ID_LIKE && $OS_ID_LIKE == *debian* ]]; then
    repo_id="debian"
  fi
  repo_suite=$OS_CODENAME
  key_dir=$(dirname "$TAILSCALE_KEY_FILE")
  list_dir=$(dirname "$TAILSCALE_LIST_FILE")
  mkdir -p "$key_dir" "$list_dir"
  key_url="https://pkgs.tailscale.com/stable/${repo_id}/${repo_suite}.noarmor.gpg"
  if ! curl -fsSL "$key_url" | gpg --dearmor > "$TAILSCALE_KEY_FILE"; then
    if [[ $repo_suite != "bookworm" ]]; then
      local fallback_url="https://pkgs.tailscale.com/stable/${repo_id}/bookworm.noarmor.gpg"
      log_warn "Tailscale key for $repo_suite unavailable; falling back to bookworm"
      if curl -fsSL "$fallback_url" | gpg --dearmor > "$TAILSCALE_KEY_FILE"; then
        repo_suite=bookworm
      else
        log_error "Failed to download Tailscale signing key from $fallback_url"
        return 1
      fi
    else
      log_error "Failed to download Tailscale signing key from $key_url"
      return 1
    fi
  fi
  chmod 644 "$TAILSCALE_KEY_FILE"
  cat <<EOF > "$TAILSCALE_LIST_FILE"
deb [signed-by=$TAILSCALE_KEY_FILE] https://pkgs.tailscale.com/stable/${repo_id} $repo_suite main
EOF
  chmod 644 "$TAILSCALE_LIST_FILE"
  log_info "Configured Tailscale repository for $repo_id $repo_suite"
  APT_UPDATED=0
  if ! apt_update_once; then
    log_warn "apt-get update encountered issues after adding Tailscale repo"
  fi
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y tailscale; then
    log_error "Failed to install tailscale package"
    return 1
  fi
  systemctl enable --now tailscale >/dev/null 2>&1 || log_warn "Unable to enable tailscale service"
  if command -v tailscale >/dev/null 2>&1; then
    if tailscale set --accept-routes=true >/dev/null 2>&1; then
      log_info "Enabled accept-routes on Tailscale client"
    else
      log_warn "tailscale set --accept-routes=true failed (device may not be logged in yet)"
    fi
  fi
}

# Install Docker Engine (upstream if possible) and enable service.
task_install_docker() {
  load_os_release
  local arch repo_id repo_configured=0
  arch=$(dpkg --print-architecture)
  repo_id=$OS_ID
  if [[ $repo_id == "raspbian" || $repo_id == "debian" ]]; then
    repo_id="debian"
  elif [[ $repo_id == "ubuntu" ]]; then
    repo_id="ubuntu"
  elif [[ -n $OS_ID_LIKE && $OS_ID_LIKE == *debian* ]]; then
    repo_id="debian"
  fi

  ensure_packages ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f "$DOCKER_KEY_FILE" ]]; then
    if curl -fsSL "https://download.docker.com/linux/${repo_id}/gpg" | gpg --dearmor > "$DOCKER_KEY_FILE"; then
      chmod a+r "$DOCKER_KEY_FILE"
      repo_configured=1
    else
      log_warn "Failed to download Docker signing key; using distribution packages"
      rm -f "$DOCKER_KEY_FILE"
    fi
  else
    repo_configured=1
  fi

  if [[ $repo_configured -eq 1 ]]; then
    local docker_suite=$OS_CODENAME
    if ! curl -fsI "https://download.docker.com/linux/${repo_id}/dists/${docker_suite}/Release" >/dev/null 2>&1; then
      if [[ $docker_suite != "bookworm" ]]; then
        log_warn "Docker repo for $docker_suite unavailable; falling back to bookworm"
        docker_suite=bookworm
      fi
    fi
    cat <<EOF > "$DOCKER_LIST_FILE"
deb [arch=$arch signed-by=$DOCKER_KEY_FILE] https://download.docker.com/linux/${repo_id} $docker_suite stable
EOF
    chmod 644 "$DOCKER_LIST_FILE"
  fi

  APT_UPDATED=0
  apt_update_once || true

  local installed=0
  if [[ $repo_configured -eq 1 ]]; then
    if DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
      installed=1
    else
      log_warn "Docker CE packages unavailable from upstream repo"
    fi
  fi

  if [[ $installed -eq 0 ]]; then
    APT_UPDATED=0
    apt_update_once || true
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-plugin; then
      log_error "Failed to install Docker packages"
      return 1
    fi
  fi

  systemctl enable --now docker >/dev/null 2>&1 || log_warn "Unable to enable docker service"
  if command -v usermod >/dev/null 2>&1; then
    local target_user=${SUDO_USER:-}
    if [[ -n $target_user && $target_user != "root" ]]; then
      usermod -aG docker "$target_user" 2>/dev/null || log_warn "Could not add $target_user to docker group"
    fi
  fi
}

# Turn off console and desktop blanking/DPMS for kiosk screens.
task_disable_screen_blanking() {
  if command -v raspi-config >/dev/null 2>&1; then
    if raspi-config nonint do_blanking 1 >/dev/null 2>&1; then
      log_info "Disabled screen blanking via raspi-config"
    else
      log_warn "raspi-config could not disable screen blanking"
    fi
  fi

  if [[ -f "$CMDLINE_FILE" ]] && ! grep -qw 'consoleblank=0' "$CMDLINE_FILE"; then
    backup_file "$CMDLINE_FILE"
    CMDLINE_PATH="$CMDLINE_FILE" python3 <<'PY'
import os
from pathlib import Path
path = Path(os.environ['CMDLINE_PATH'])
content = path.read_text().strip()
parts = content.split()
if "consoleblank=0" not in parts:
    parts.append("consoleblank=0")
    path.write_text(" ".join(parts) + "\n")
PY
    log_info "Added consoleblank=0 to cmdline.txt"
  fi

  if [[ -f /etc/kbd/config ]]; then
    backup_file /etc/kbd/config
    if grep -q '^BLANK_TIME=' /etc/kbd/config; then
      sed -i 's/^BLANK_TIME=.*/BLANK_TIME=0/' /etc/kbd/config
    else
      echo 'BLANK_TIME=0' >> /etc/kbd/config
    fi
    if grep -q '^POWERDOWN_TIME=' /etc/kbd/config; then
      sed -i 's/^POWERDOWN_TIME=.*/POWERDOWN_TIME=0/' /etc/kbd/config
    else
      echo 'POWERDOWN_TIME=0' >> /etc/kbd/config
    fi
    log_info "Configured console blanking and powerdown timers to 0"
  fi

  local lightdm_dir
  lightdm_dir=$(dirname "$LIGHTDM_NOBLANK_FILE")
  if [[ -d "$lightdm_dir" ]]; then
    cat <<'CFG' > "$LIGHTDM_NOBLANK_FILE"
[Seat:*]
xserver-command=X -s 0 -dpms
CFG
    log_info "Configured LightDM to disable DPMS and screen blanking"
  fi

  return 0
}


# Relocate /var/log to tmpfs with supporting tmpfiles rules.
task_mount_var_log_tmpfs() {
  if [[ -d /var/log/journal ]]; then
    if command -v journalctl >/dev/null 2>&1; then
      journalctl --rotate >/dev/null 2>&1 || true
      journalctl --vacuum-time=1s >/dev/null 2>&1 || true
    fi
    if find /var/log/journal -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
      local backup_tar
      backup_tar=/var/log.journal-backup.pi-optimiser.$(date +%Y%m%d%H%M%S).tar.gz
      if tar -czf "$backup_tar" -C /var/log journal >/dev/null 2>&1; then
        log_info "Archived existing journal to $backup_tar"
        rm -rf /var/log/journal/* 2>/dev/null || true
      else
        log_warn "Failed to archive /var/log/journal prior to tmpfs mount"
      fi
    fi
  fi

  if grep -Eq '^tmpfs\s+/var/log\s+tmpfs' /etc/fstab; then
    log_info "/var/log already configured in fstab"
  else
    backup_file /etc/fstab
    echo "$VAR_LOG_TMPFS_ENTRY" >> /etc/fstab
    log_info "Added tmpfs entry for /var/log"
  fi

  cat <<'CFG' > "$VAR_LOG_TMPFILES"
d /var/log 0755 root root -
d /var/log/apt 0755 root root -
d /var/log/lightdm 0755 root root -
d /var/log/samba 0755 root root -
d /var/log/cups 0755 root lp -
d /var/log/journal 2755 root systemd-journal -
d /var/log/private 0700 root root -
CFG
  log_info "Ensured tmpfiles.d definition for /var/log exists"

  if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "$VAR_LOG_TMPFILES" >/dev/null 2>&1 || true
  fi

  if mountpoint -q /var/log; then
    if ! findmnt -n /var/log | grep -q 'tmpfs'; then
      mount -o remount /var/log >/dev/null 2>&1 || true
    fi
  else
    mount /var/log >/dev/null 2>&1 || true
  fi
}


# Apply vc4 KMS display defaults when supported by hardware.
task_optimize_boot_config() {
  if ! pi_supports_kms_overlays; then
    log_info "Skipping boot config tuning (model ${SYSTEM_MODEL:-unknown} does not support vc4-kms presets)"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (model unsupported)"
    return 0
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_info "config.txt not present; skipping boot config tuning"
    return 0
  fi
  backup_file "$CONFIG_TXT_FILE"
  local -a entries=(
    "dtoverlay=vc4-kms-v3d"
    "gpu_mem=320"
    "disable_overscan=1"
    "hdmi_force_hotplug=1"
    "framebuffer_depth=32"
    "framebuffer_ignore_alpha=1"
    "dtparam=audio=on"
    "arm_boost=1"
  )
  local applied=0
  local entry rc safe_key
  for entry in "${entries[@]}"; do
    if ensure_config_line "$entry"; then
      log_info "Applied $entry to config.txt"
      safe_key=${entry//=/_}
      write_json_field "$CONFIG_OPTIMISER_STATE" "boot_config.${safe_key}" "$entry"
      applied=1
    else
      rc=$?
      if [[ $rc -gt 1 ]]; then
        log_warn "Failed to ensure $entry in config.txt"
      fi
    fi
  done
  if [[ $applied -eq 1 ]]; then
    log_info "Boot config tuned for Raspberry Pi desktop display"
  else
    log_info "Boot config already matched recommended defaults"
  fi
}

# Ensure vc4 overlays disable liftoff to prevent compositor glitches.
task_disable_libliftoff_overlays() {
  if ! pi_supports_kms_overlays; then
    log_info "Skipping libliftoff overlay tuning (model ${SYSTEM_MODEL:-unknown} lacks vc4-kms)"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (model unsupported)"
    return 0
  fi
  local cfg="$CONFIG_TXT_FILE"
  if [[ ! -f "$cfg" ]]; then
    log_info "config.txt not present; skipping libliftoff tuning"
    return 0
  fi
  if ! grep -qi 'liftoff' "$cfg" && ! grep -qi 'vc4-kms-v3d' "$cfg"; then
    log_info "No vc4-kms liftoff settings detected"
    return 0
  fi
  backup_file "$cfg"
  local result
  result=$(CONFIG_FILE="$cfg" python3 <<'PY'
import os
from pathlib import Path
cfg_path = Path(os.environ['CONFIG_FILE'])
lines = cfg_path.read_text().splitlines()
changed = False
new_lines = []
for line in lines:
    stripped = line.lstrip()
    prefix = line[:len(line) - len(stripped)]
    commented = False
    if stripped.startswith('#'):
        after_hash = stripped[1:].lstrip()
        if after_hash.lower().startswith('dtoverlay'):
            stripped = after_hash
            commented = True
    lower = stripped.lower()
    if lower.startswith('dtoverlay') and ('liftoff' in lower or 'vc4-kms-v3d' in lower):
        try:
            key, value = stripped.split('=', 1)
        except ValueError:
            new_lines.append(prefix + stripped)
            continue
        opts = [opt for opt in value.split(',') if opt]
        cleaned_opts = []
        liftoff_disabled = False
        for opt in opts:
            opt_lower = opt.strip().lower()
            if opt_lower in {'liftoff', 'liftoff=1', 'liftoff=on'}:
                changed = True
                continue
            if opt_lower in {'no-liftoff', 'liftoff=0', 'liftoff=off', 'disable_liftoff=1'}:
                liftoff_disabled = True
            cleaned_opts.append(opt)
        if not liftoff_disabled:
            cleaned_opts.append('no-liftoff')
            liftoff_disabled = True
        new_value = ','.join(cleaned_opts)
        new_line = f"{key}={new_value}"
        if commented or new_line != stripped:
            changed = True
        stripped = new_line
    new_lines.append(prefix + stripped)
if changed:
    cfg_path.write_text('\n'.join(new_lines) + '\n')
print('changed' if changed else 'unchanged')
PY
  )
  result=${result//$'\n'/}
  if [[ $result == "changed" ]]; then
    log_info "Ensured libliftoff is disabled while keeping KMS overlays active"
  else
    log_info "libliftoff settings already optimal"
  fi
}


# Apply vendor-safe CPU/GPU overclock profiles for Pi 5/500/4/400/3/Zero 2.
task_configure_conservative_oc() {
  if [[ $REQUEST_OC_CONSERVATIVE -eq 0 ]]; then
    log_info "Conservative overclock not requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  if [[ $POWER_HEALTHY -eq 0 ]]; then
    log_warn "Skipping conservative overclock because preflight reported power/thermal issues"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (preflight power/thermal issues)"
    return 0
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot apply conservative overclock"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (config.txt missing)"
    return 0
  fi

  local -a entries=()
  local profile=""
  local model_lower=${SYSTEM_MODEL,,}
  if pi_is_generation 5 || [[ $model_lower == *"raspberry pi 500"* ]]; then
    entries=(
      "over_voltage_delta=30000"
      "arm_freq=2800"
      "gpu_freq=950"
    )
    profile="pi5_2800mhz"
  elif [[ $model_lower == *"raspberry pi 400"* ]]; then
    entries=(
      "arm_freq=2000"
      "gpu_freq=600"
    )
    profile="pi400_conservative"
  elif pi_is_generation 4; then
    entries=(
      "arm_freq=1750"
      "gpu_freq=600"
    )
    profile="pi4_conservative"
  elif pi_is_generation 3; then
    entries=(
      "arm_freq=1400"
      "gpu_freq=500"
    )
    profile="pi3_conservative"
  elif pi_is_generation zero2; then
    entries=(
      "arm_freq=1200"
      "gpu_freq=500"
    )
    profile="pi_zero2_conservative"
  else
    log_info "Conservative overclock not supported on model ${SYSTEM_MODEL:-unknown}"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (model unsupported)"
    return 0
  fi

  backup_file "$CONFIG_TXT_FILE"
  local applied=0 entry safe_key rc
  for entry in "${entries[@]}"; do
    rc=0
    ensure_config_key_value "$entry" "$CONFIG_TXT_FILE" || rc=$?
    if [[ $rc -eq 0 ]]; then
      log_info "Applied $entry to config.txt"
      safe_key=${entry//=/_}
      write_json_field "$CONFIG_OPTIMISER_STATE" "overclock.${safe_key}" "$entry"
      applied=1
    elif [[ $rc -gt 1 ]]; then
      log_warn "Failed to apply $entry to config.txt"
    fi
  done
  if [[ $applied -eq 1 ]]; then
    write_json_field "$CONFIG_OPTIMISER_STATE" "overclock.profile" "$profile"
    log_info "Conservative overclock profile applied: $profile"
  else
    log_info "Overclock profile already present"
  fi
}


# Harden sshd configuration and enable fail2ban protection.
task_secure_ssh() {
  if [[ $SECURE_SSH -eq 0 ]]; then
    log_info "Secure SSH not requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi

  local ssh_config=/etc/ssh/sshd_config
  if [[ ! -f "$ssh_config" ]]; then
    log_warn "sshd_config not found; skipping SSH hardening"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (sshd_config missing)"
    return 0
  fi

  # Stage fail2ban first so brute-force protection is live before sshd reloads.
  ensure_packages fail2ban
  local jail_dir=/etc/fail2ban/jail.d
  local jail_file=$jail_dir/pi-optimiser-ssh.conf
  mkdir -p "$jail_dir"
  cat <<'JAIL' > "$jail_file"
[sshd]
enabled = true
port    = ssh
maxretry = 5
findtime = 600
bantime  = 600
backend = systemd
JAIL
  log_info "Configured fail2ban jail for sshd"

  systemctl enable --now fail2ban >/dev/null 2>&1 || log_warn "Unable to enable fail2ban service"
  systemctl restart fail2ban >/dev/null 2>&1 || true

  backup_file "$ssh_config"
  update_sshd_config_option "PermitRootLogin" "no"
  update_sshd_config_option "PasswordAuthentication" "yes"
  update_sshd_config_option "ChallengeResponseAuthentication" "no"
  update_sshd_config_option "UsePAM" "yes"

  if ! sshd -t -f "$ssh_config" >/dev/null 2>&1; then
    log_error "sshd configuration validation failed after hardening"
    return 1
  fi

  if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
    systemctl reload ssh >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || log_warn "Unable to reload ssh service"
  fi

  write_json_field "$CONFIG_OPTIMISER_STATE" "security.ssh.permit_root" "no"
  write_json_field "$CONFIG_OPTIMISER_STATE" "security.ssh.fail2ban" "enabled"

  log_info "SSH hardened and fail2ban enabled"
}


# Install systemd service that pins the CPU scaling governor to performance.
task_configure_cpu_governor() {
  if [[ ! -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
    log_info "cpufreq not exposed by kernel; skipping governor pinning"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (cpufreq unavailable)"
    return 0
  fi

  mkdir -p "$(dirname "$CPU_GOVERNOR_SERVICE")"
  cat <<'CFG' > "$CPU_GOVERNOR_SERVICE"
[Unit]
Description=Pin CPU scaling governor to performance (pi-optimiser)
After=multi-user.target
ConditionPathExists=/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -w "$g" ] && echo performance > "$g" || true; done'

[Install]
WantedBy=multi-user.target
CFG
  chmod 644 "$CPU_GOVERNOR_SERVICE"

  systemctl daemon-reload >/dev/null 2>&1 || true
  if ! systemctl enable pi-optimiser-cpu-governor.service >/dev/null 2>&1; then
    log_warn "Unable to enable pi-optimiser-cpu-governor.service"
  fi

  local g changed=0
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -w "$g" ]] || continue
    if echo performance > "$g" 2>/dev/null; then
      changed=1
    fi
  done
  if (( changed == 1 )); then
    log_info "CPU scaling governor set to performance"
  else
    log_warn "Unable to write scaling_governor; service will apply on next boot"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "cpu.governor" "performance"
}


# Apply SDRAM_BANKLOW tuning to the Raspberry Pi bootloader EEPROM.
task_configure_eeprom() {
  if ! command -v rpi-eeprom-config >/dev/null 2>&1; then
    log_info "rpi-eeprom-config not available; skipping EEPROM tuning"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (rpi-eeprom-config missing)"
    return 0
  fi

  local bank_value=""
  local profile=""
  local model_lower=${SYSTEM_MODEL,,}
  if pi_is_generation 5 || [[ $model_lower == *"raspberry pi 500"* ]]; then
    bank_value=1
    profile="pi5"
  elif [[ $model_lower == *"raspberry pi 400"* ]]; then
    bank_value=3
    profile="pi400"
  elif pi_is_generation 4; then
    bank_value=3
    profile="pi4"
  else
    log_info "EEPROM SDRAM tuning not applicable for model ${SYSTEM_MODEL:-unknown}"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (model unsupported)"
    return 0
  fi

  mkdir -p "$EEPROM_STAGING_DIR"
  chmod 755 "$EEPROM_STAGING_DIR"

  local current_conf new_conf
  current_conf=$(mktemp)
  new_conf=$(mktemp)

  if ! rpi-eeprom-config > "$current_conf" 2>/dev/null; then
    log_warn "Unable to read current EEPROM configuration"
    rm -f "$current_conf" "$new_conf"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (could not read eeprom config)"
    return 0
  fi

  CONF_IN="$current_conf" CONF_OUT="$new_conf" BANK_VALUE="$bank_value" python3 <<'PY'
import os
from pathlib import Path

src = Path(os.environ['CONF_IN'])
dst = Path(os.environ['CONF_OUT'])
bank_value = os.environ['BANK_VALUE']

lines = src.read_text().splitlines() if src.exists() else []
out = []
found = False
for line in lines:
    candidate = line.strip().lstrip('#').strip()
    if candidate.upper().startswith('SDRAM_BANKLOW='):
        if not found:
            out.append(f"SDRAM_BANKLOW={bank_value}")
            found = True
        continue
    out.append(line)
if not found:
    out.append(f"SDRAM_BANKLOW={bank_value}")
dst.write_text('\n'.join(out) + '\n')
PY

  cp "$new_conf" "$EEPROM_STAGING_DIR/boot.conf.pending" 2>/dev/null || true

  if diff -q "$current_conf" "$new_conf" >/dev/null 2>&1; then
    log_info "EEPROM config already has SDRAM_BANKLOW=$bank_value"
    rm -f "$current_conf" "$new_conf"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.sdram_banklow" "$bank_value"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.profile" "$profile"
    return 0
  fi

  local backup_path
  backup_path="$EEPROM_STAGING_DIR/boot.conf.$(date +%Y%m%d%H%M%S).bak"
  cp "$current_conf" "$backup_path" 2>/dev/null || true

  if rpi-eeprom-config --apply "$new_conf" >/dev/null 2>&1; then
    log_info "Applied SDRAM_BANKLOW=$bank_value to EEPROM (profile: $profile); active after reboot"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.sdram_banklow" "$bank_value"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.profile" "$profile"
    rm -f "$current_conf" "$new_conf"
    return 0
  fi

  log_warn "rpi-eeprom-config --apply failed; EEPROM unchanged (staged config at $EEPROM_STAGING_DIR/boot.conf.pending)"
  rm -f "$current_conf" "$new_conf"
  return 1
}


# Install latest Raspberry Pi firmware via rpi-update (opt-in, non-interactive).
task_firmware_update() {
  if [[ $FIRMWARE_UPDATE -eq 0 ]]; then
    log_info "Firmware update via rpi-update not requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  if ! command -v rpi-update >/dev/null 2>&1; then
    log_warn "rpi-update not installed; skipping firmware update"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (rpi-update missing)"
    return 0
  fi
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Network unavailable; skipping rpi-update"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (network unavailable)"
    return 0
  fi

  log_info "Running rpi-update non-interactively (SKIP_WARNING=1)"
  # Pipe 'y' into stdin as a belt-and-suspenders guard for any future prompts.
  # Disable pipefail so yes(1) getting SIGPIPE doesn't mask rpi-update's exit
  # code; `|| rpi_update_rc=$?` prevents `set -e` from firing on a real failure
  # and captures rpi-update's status.
  local rpi_update_rc=0
  set +o pipefail
  yes y | SKIP_WARNING=1 rpi-update || rpi_update_rc=$?
  set -o pipefail
  if [[ $rpi_update_rc -eq 0 ]]; then
    log_info "rpi-update completed; reboot required to activate new firmware"
    write_json_field "$CONFIG_OPTIMISER_STATE" "firmware.last_update" "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
    return 0
  fi
  log_warn "rpi-update returned exit code $rpi_update_rc"
  return 1
}


# Enable fstrim.timer for periodic TRIM on SSD/NVMe/eMMC roots.
task_enable_fstrim() {
  if ! systemctl list-unit-files fstrim.timer >/dev/null 2>&1; then
    log_info "fstrim.timer unit not available; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (fstrim.timer missing)"
    return 0
  fi
  if ! systemctl enable --now fstrim.timer >/dev/null 2>&1; then
    log_warn "Unable to enable fstrim.timer"
    return 1
  fi
  log_info "Enabled fstrim.timer for weekly SSD/NVMe TRIM"
  write_json_field "$CONFIG_OPTIMISER_STATE" "fstrim.enabled" "true"
}


# Set the system timezone when requested via --timezone.
task_configure_timezone() {
  if [[ -z "$REQUESTED_TIMEZONE" ]]; then
    log_info "No timezone requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  if [[ ! -f "/usr/share/zoneinfo/$REQUESTED_TIMEZONE" ]]; then
    log_error "Timezone '$REQUESTED_TIMEZONE' not found under /usr/share/zoneinfo"
    return 1
  fi
  if command -v timedatectl >/dev/null 2>&1; then
    if ! timedatectl set-timezone "$REQUESTED_TIMEZONE" >/dev/null 2>&1; then
      log_error "timedatectl failed to set timezone to $REQUESTED_TIMEZONE"
      return 1
    fi
  else
    ln -sf "/usr/share/zoneinfo/$REQUESTED_TIMEZONE" /etc/localtime
    echo "$REQUESTED_TIMEZONE" > /etc/timezone
  fi
  log_info "System timezone set to $REQUESTED_TIMEZONE"
  write_json_field "$CONFIG_OPTIMISER_STATE" "timezone.name" "$REQUESTED_TIMEZONE"
}


# Set the system hostname when requested via --hostname.
task_configure_hostname() {
  if [[ -z "$REQUESTED_HOSTNAME" ]]; then
    log_info "No hostname requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  if ! [[ $REQUESTED_HOSTNAME =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
    log_error "Invalid hostname '$REQUESTED_HOSTNAME' (must be RFC 1123 label)"
    return 1
  fi
  local old_hostname
  old_hostname=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "raspberrypi")
  if command -v hostnamectl >/dev/null 2>&1; then
    hostnamectl set-hostname "$REQUESTED_HOSTNAME"
  else
    echo "$REQUESTED_HOSTNAME" > /etc/hostname
    hostname "$REQUESTED_HOSTNAME" >/dev/null 2>&1 || true
  fi
  if [[ -f /etc/hosts ]]; then
    backup_file /etc/hosts
    OLD_HN="$old_hostname" NEW_HN="$REQUESTED_HOSTNAME" python3 <<'PY'
import os
from pathlib import Path
path = Path('/etc/hosts')
old = os.environ['OLD_HN']
new = os.environ['NEW_HN']
lines = path.read_text().splitlines()
out = []
for line in lines:
    stripped = line.strip()
    if stripped.startswith('127.0.1.1'):
        parts = line.split()
        if len(parts) >= 2:
            parts = [parts[0], new] + [p for p in parts[2:] if p != old]
            out.append('\t'.join(parts))
            continue
    out.append(line)
have_127_0_1_1 = any(l.strip().startswith('127.0.1.1') for l in out)
if not have_127_0_1_1:
    out.append(f"127.0.1.1\t{new}")
path.write_text('\n'.join(out) + '\n')
PY
  fi
  log_info "System hostname set to $REQUESTED_HOSTNAME"
  write_json_field "$CONFIG_OPTIMISER_STATE" "hostname.name" "$REQUESTED_HOSTNAME"
}


# Import authorized_keys from a GitHub user and/or arbitrary HTTPS URL.
task_ssh_import_keys() {
  if [[ -z "$SSH_IMPORT_GITHUB" && -z "$SSH_IMPORT_URL" ]]; then
    log_info "No SSH key import requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  ensure_packages curl ca-certificates
  local target_user=${SUDO_USER:-}
  if [[ -z "$target_user" || "$target_user" == "root" ]]; then
    target_user=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
  fi
  if [[ -z "$target_user" ]]; then
    log_warn "Unable to determine target user for SSH key import"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (no target user)"
    return 0
  fi
  local home_dir
  home_dir=$(getent passwd "$target_user" | cut -d: -f6)
  if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
    log_warn "Home directory for $target_user not found"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (home missing)"
    return 0
  fi
  local ssh_dir="$home_dir/.ssh"
  local authorized="$ssh_dir/authorized_keys"
  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  touch "$authorized"
  chmod 600 "$authorized"
  chown -R "$target_user:$target_user" "$ssh_dir"

  local tmp_keys
  tmp_keys=$(mktemp)
  local imported=0

  if [[ -n "$SSH_IMPORT_GITHUB" ]]; then
    local gh_url="https://github.com/${SSH_IMPORT_GITHUB}.keys"
    if curl -fsSL "$gh_url" -o "$tmp_keys" && [[ -s "$tmp_keys" ]]; then
      KEYS_FILE="$tmp_keys" AUTH_FILE="$authorized" SRC="github:$SSH_IMPORT_GITHUB" python3 <<'PY'
import os
from pathlib import Path
keys = Path(os.environ['KEYS_FILE']).read_text().splitlines()
auth = Path(os.environ['AUTH_FILE'])
existing = set()
if auth.exists():
    for line in auth.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            existing.add(stripped.split()[-1] if len(stripped.split()) >= 3 else stripped)
added = []
for key in keys:
    key = key.strip()
    if not key or key.startswith('#'):
        continue
    parts = key.split()
    marker = parts[-1] if len(parts) >= 3 else key
    if marker in existing:
        continue
    added.append(key)
    existing.add(marker)
if added:
    with auth.open('a') as fh:
        fh.write(f"\n# pi-optimiser import: {os.environ['SRC']}\n")
        for k in added:
            fh.write(k + "\n")
print(len(added))
PY
      imported=1
      log_info "Imported SSH keys from $gh_url into $authorized"
    else
      log_warn "Failed to fetch GitHub keys from $gh_url"
    fi
  fi

  if [[ -n "$SSH_IMPORT_URL" ]]; then
    if [[ $SSH_IMPORT_URL != https://* ]]; then
      log_error "--ssh-import-url must use https://"
      rm -f "$tmp_keys"
      return 1
    fi
    if curl -fsSL "$SSH_IMPORT_URL" -o "$tmp_keys" && [[ -s "$tmp_keys" ]]; then
      KEYS_FILE="$tmp_keys" AUTH_FILE="$authorized" SRC="url:$SSH_IMPORT_URL" python3 <<'PY'
import os
from pathlib import Path
keys = Path(os.environ['KEYS_FILE']).read_text().splitlines()
auth = Path(os.environ['AUTH_FILE'])
existing = set()
if auth.exists():
    for line in auth.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            existing.add(stripped.split()[-1] if len(stripped.split()) >= 3 else stripped)
added = []
for key in keys:
    key = key.strip()
    if not key or key.startswith('#'):
        continue
    parts = key.split()
    marker = parts[-1] if len(parts) >= 3 else key
    if marker in existing:
        continue
    added.append(key)
    existing.add(marker)
if added:
    with auth.open('a') as fh:
        fh.write(f"\n# pi-optimiser import: {os.environ['SRC']}\n")
        for k in added:
            fh.write(k + "\n")
PY
      imported=1
      log_info "Imported SSH keys from $SSH_IMPORT_URL into $authorized"
    else
      log_warn "Failed to fetch keys from $SSH_IMPORT_URL"
    fi
  fi

  rm -f "$tmp_keys"
  chown "$target_user:$target_user" "$authorized"
  chmod 600 "$authorized"

  if [[ $imported -eq 0 ]]; then
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (no keys imported)"
  else
    write_json_field "$CONFIG_OPTIMISER_STATE" "ssh.keys_imported_for" "$target_user"
  fi
}


# Enable the Raspberry Pi hardware watchdog and wire systemd to feed it.
task_enable_watchdog() {
  if [[ $INSTALL_WATCHDOG -eq 0 ]]; then
    log_info "Hardware watchdog not requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot enable watchdog"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (config.txt missing)"
    return 0
  fi
  backup_file "$CONFIG_TXT_FILE"
  local rc=0
  ensure_config_key_value "dtparam=watchdog=on" "$CONFIG_TXT_FILE" || rc=$?
  if [[ $rc -eq 0 ]]; then
    log_info "Enabled dtparam=watchdog=on in config.txt"
  elif [[ $rc -gt 1 ]]; then
    log_warn "Failed to set watchdog dtparam"
  fi

  local watchdog_dir=/etc/systemd/system.conf.d
  mkdir -p "$watchdog_dir"
  cat <<'CFG' > "$watchdog_dir/99-pi-optimiser-watchdog.conf"
[Manager]
RuntimeWatchdogSec=15
ShutdownWatchdogSec=10min
CFG
  systemctl daemon-reload >/dev/null 2>&1 || true
  log_info "Configured systemd RuntimeWatchdogSec=15; active after reboot"
  write_json_field "$CONFIG_OPTIMISER_STATE" "watchdog.enabled" "true"
}


# Apply a Pi 5 PWM fan curve to config.txt (temperatures in millidegrees).
task_configure_pi5_fan_profile() {
  if [[ $INSTALL_PI5_FAN_PROFILE -eq 0 ]]; then
    log_info "Pi 5 fan profile not requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  local model_lower=${SYSTEM_MODEL,,}
  if ! pi_is_generation 5 && [[ $model_lower != *"raspberry pi 500"* ]]; then
    log_info "Pi 5 fan profile only applies to Pi 5/500; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (model unsupported)"
    return 0
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot apply fan profile"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (config.txt missing)"
    return 0
  fi
  backup_file "$CONFIG_TXT_FILE"
  local -a entries=(
    "dtparam=fan_temp0=50000"
    "dtparam=fan_temp0_hyst=5000"
    "dtparam=fan_temp0_speed=75"
    "dtparam=fan_temp1=60000"
    "dtparam=fan_temp1_hyst=5000"
    "dtparam=fan_temp1_speed=125"
    "dtparam=fan_temp2=67000"
    "dtparam=fan_temp2_hyst=5000"
    "dtparam=fan_temp2_speed=200"
    "dtparam=fan_temp3=75000"
    "dtparam=fan_temp3_hyst=5000"
    "dtparam=fan_temp3_speed=255"
  )
  local entry rc applied=0
  for entry in "${entries[@]}"; do
    rc=0
    ensure_config_key_value "$entry" "$CONFIG_TXT_FILE" || rc=$?
    if [[ $rc -eq 0 ]]; then
      applied=1
    elif [[ $rc -gt 1 ]]; then
      log_warn "Failed to apply $entry"
    fi
  done
  if [[ $applied -eq 1 ]]; then
    log_info "Applied Pi 5 PWM fan curve (50/60/67/75 C)"
  else
    log_info "Pi 5 fan curve already present"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "fan.profile" "pi5_50_60_67_75"
}


# Refresh the Raspberry Pi bootloader EEPROM via rpi-eeprom-update.
task_eeprom_update() {
  if [[ $EEPROM_UPDATE -eq 0 ]]; then
    log_info "Bootloader EEPROM update not requested; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (not requested)"
    return 0
  fi
  if ! command -v rpi-eeprom-update >/dev/null 2>&1; then
    log_warn "rpi-eeprom-update not available; skipping"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (rpi-eeprom-update missing)"
    return 0
  fi
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Network unavailable; skipping rpi-eeprom-update"
    TASK_WAS_SKIPPED=1
    TASK_SKIP_REASON="$CURRENT_TASK (network unavailable)"
    return 0
  fi

  local out rc=0
  out=$(rpi-eeprom-update -a 2>&1) || rc=$?
  if [[ $rc -eq 0 ]]; then
    log_info "rpi-eeprom-update -a completed; reboot required to apply new EEPROM"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.last_update" "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
    return 0
  fi
  log_warn "rpi-eeprom-update returned exit code $rc"
  log_warn "Output: $out"
  return 1
}


TASK_DEFS=(
  "remove_bloat:task_remove_bloat_packages:Remove bundled educational/demo packages"
  "fstab:task_tune_fstab:Tune filesystem mounts for reduced writes"
  "tmpfs_tmp:task_mount_tmp_tmpfs:Ensure /tmp is mounted as tmpfs"
  "var_log_tmpfs:task_mount_var_log_tmpfs:Keep /var/log in RAM to reduce writes"
  "disable_swap:task_disable_swap:Disable swap file service (requires 2GB+ RAM recommended)"
  "zram:task_configure_zram:Configure compressed ZRAM swap sized to system memory"
  "fstrim:task_enable_fstrim:Enable weekly fstrim.timer for SSD/NVMe TRIM"
  "journald:task_configure_journald:Limit systemd journal writes to RAM"
  "sysctl:task_configure_sysctl:Tune kernel memory and writeback behaviour"
  "cpu_governor:task_configure_cpu_governor:Pin CPU scaling governor to performance via systemd"
  "apt_conf:task_configure_apt:Reduce apt cache usage and auto updates"
  "unattended:task_configure_unattended_upgrades:Enable unattended security upgrades (6h cadence)"
  "cli_tools:task_install_cli_tools:Ensure essential CLI tools are installed"
  "locale:task_configure_locale:Set default system locale"
  "timezone:task_configure_timezone:Set system timezone when --timezone is provided"
  "hostname:task_configure_hostname:Set system hostname when --hostname is provided"
  "limits:task_configure_limits:Raise system file and process limits"
  "screen_blanking:task_disable_screen_blanking:Disable console and desktop screen blanking"
  "disable_services:task_disable_services:Disable non-essential background services"
  "proxy:task_configure_proxy:Expose a backend via nginx reverse proxy on port 80"
  "boot_config:task_optimize_boot_config:Tune /boot/firmware/config.txt for kiosk display stability"
  "libliftoff:task_disable_libliftoff_overlays:Ensure vc4 KMS overlays keep liftoff disabled"
  "oc_conservative:task_configure_conservative_oc:Apply Raspberry Pi overclock profile (Pi 5/500 2.8 GHz)"
  "eeprom_config:task_configure_eeprom:Tune Raspberry Pi EEPROM SDRAM_BANKLOW for Pi 4/400/5/500"
  "pi5_fan:task_configure_pi5_fan_profile:Apply Pi 5 PWM fan curve when --pi5-fan-profile is provided"
  "watchdog:task_enable_watchdog:Enable hardware watchdog when --enable-watchdog is provided"
  "ssh_import:task_ssh_import_keys:Import SSH authorized_keys from GitHub/URL"
  "secure_ssh:task_secure_ssh:Harden sshd configuration and enable fail2ban"
  "tailscale:task_setup_tailscale:Install and enable Tailscale"
  "docker:task_install_docker:Install Docker Engine and enable service"
  "eeprom_refresh:task_eeprom_update:Refresh bootloader EEPROM via rpi-eeprom-update (opt-in)"
  "firmware_update:task_firmware_update:Run rpi-update non-interactively (opt-in)"
)

# Ensure /tmp lives on tmpfs to reduce SD card writes.
task_mount_tmp_tmpfs() {
  if grep -E "^\s*tmpfs\s+/tmp\s+tmpfs" /etc/fstab >/dev/null; then
    log_info "/tmp already defined as tmpfs"
    if mountpoint -q /tmp && findmnt -n /tmp | grep -q "tmpfs"; then
      return 0
    fi
  fi
  backup_file /etc/fstab
  if ! grep -E "^\s*tmpfs\s+/tmp\s+tmpfs" /etc/fstab >/dev/null; then
    echo "$TMPFS_ENTRY" >> /etc/fstab
    log_info "Appended tmpfs entry for /tmp"
  fi
  if mountpoint -q /tmp; then
    mount -o remount /tmp >/dev/null 2>&1 || true
  else
    mount /tmp >/dev/null 2>&1 || true
  fi
}

# Entry point orchestrating argument parsing and task execution.
main() {
  parse_args "$@"
  if [[ $LIST_TASKS -eq 1 ]]; then
    list_tasks
    exit 0
  fi
  require_root
  init_logging
  trap 'on_err $? $LINENO' ERR
  ensure_marker_store
  load_os_release
  gather_system_info
  preflight_checks
  if [[ $STATUS_ONLY -eq 1 ]]; then
    print_status
    exit 0
  fi
  log_info "Starting pi-optimiser version $SCRIPT_VERSION"
  local entry task func desc
  for entry in "${TASK_DEFS[@]}"; do
    IFS=: read -r task func desc <<< "$entry"
    if [[ "$task" == "tailscale" && $INSTALL_TAILSCALE -eq 0 ]]; then
      log_info "Skipping tailscale task (enable with --install-tailscale)"
      SUMMARY_SKIPPED+=("$task (tailscale not requested)")
      continue
    fi
    if [[ "$task" == "docker" && $INSTALL_DOCKER -eq 0 ]]; then
      log_info "Skipping docker task (enable with --install-docker)"
      SUMMARY_SKIPPED+=("$task (docker not requested)")
      continue
    fi
    if [[ "$task" == "firmware_update" && $FIRMWARE_UPDATE -eq 0 ]]; then
      log_info "Skipping firmware_update task (enable with --firmware-update)"
      SUMMARY_SKIPPED+=("$task (firmware update not requested)")
      continue
    fi
    if [[ "$task" == "eeprom_refresh" && $EEPROM_UPDATE -eq 0 ]]; then
      log_info "Skipping eeprom_refresh task (enable with --eeprom-update)"
      SUMMARY_SKIPPED+=("$task (eeprom update not requested)")
      continue
    fi
    if [[ "$task" == "watchdog" && $INSTALL_WATCHDOG -eq 0 ]]; then
      log_info "Skipping watchdog task (enable with --enable-watchdog)"
      SUMMARY_SKIPPED+=("$task (watchdog not requested)")
      continue
    fi
    if [[ "$task" == "pi5_fan" && $INSTALL_PI5_FAN_PROFILE -eq 0 ]]; then
      log_info "Skipping pi5_fan task (enable with --pi5-fan-profile)"
      SUMMARY_SKIPPED+=("$task (fan profile not requested)")
      continue
    fi
    if [[ "$task" == "ssh_import" && -z "$SSH_IMPORT_GITHUB" && -z "$SSH_IMPORT_URL" ]]; then
      log_info "Skipping ssh_import task (enable with --ssh-import-github or --ssh-import-url)"
      SUMMARY_SKIPPED+=("$task (ssh import not requested)")
      continue
    fi
    if [[ "$task" == "timezone" && -z "$REQUESTED_TIMEZONE" ]]; then
      log_info "Skipping timezone task (enable with --timezone <tz>)"
      SUMMARY_SKIPPED+=("$task (timezone not requested)")
      continue
    fi
    if [[ "$task" == "hostname" && -z "$REQUESTED_HOSTNAME" ]]; then
      log_info "Skipping hostname task (enable with --hostname <name>)"
      SUMMARY_SKIPPED+=("$task (hostname not requested)")
      continue
    fi
    if [[ "$task" == "zram" ]]; then
      if [[ $ZRAM_ALGO_OVERRIDE != "disabled" && $INSTALL_ZRAM -eq 0 ]]; then
        log_info "Skipping zram task (enable with --install-zram)"
        SUMMARY_SKIPPED+=("$task (zram not requested)")
        continue
      fi
    fi
    if [[ "$task" == "screen_blanking" && $KEEP_SCREEN_BLANKING -eq 1 ]]; then
      log_info "Skipping screen_blanking task (requested keep-screen-blanking)"
      SUMMARY_SKIPPED+=("$task (screen blanking preserved)")
      continue
    fi
    if ! should_run_task "$task"; then
      log_info "Skipping $task (filtered)"
      SUMMARY_SKIPPED+=("$task (filtered)")
      continue
    fi
    if [[ $POWER_HEALTHY -eq 0 ]] && is_power_sensitive_task "$task"; then
      local reason="$task (skipped: power/thermal preflight blocker)"
      log_warn "Skipping $task because preflight detected power/thermal issues"
      SUMMARY_SKIPPED+=("$reason")
      continue
    fi
    if [[ "$task" == "proxy" && -n "$PROXY_BACKEND" ]]; then
      local current_backend
      if current_backend=$(get_stored_proxy_backend); then
        if [[ "$current_backend" != "$PROXY_BACKEND" ]]; then
          log_info "Proxy backend changed from '$current_backend' to '$PROXY_BACKEND'; re-running configuration"
          clear_task_state "$task"
        fi
      else
        clear_task_state "$task"
      fi
    fi
    apply_once "$task" "$desc" "$func"
  done
  print_run_summary
  log_info "Optimisation run complete"
}

main "$@"
