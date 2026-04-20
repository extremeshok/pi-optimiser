#!/usr/bin/env bash
# ======================================================================
# Coded by Adrian Jon Kriel :: admin@extremeshok.com
# Project home: https://github.com/extremeshok/pi-optimiser
# ======================================================================
# pi-optimiser.sh :: version 9.3.0
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
SCRIPT_VERSION="9.3.0"

# Globals consumed by sourced lib/util/*.sh modules; shellcheck cannot
# see across source boundaries so SC2034 would flag them spuriously.
# shellcheck disable=SC2034
MARKER_DIR="/etc/pi-optimiser"
# shellcheck disable=SC2034
STATE_FILE="$MARKER_DIR/state"
# Path constants consumed by lib/tasks/*.sh — all intentionally
# referenced across source boundaries, so SC2034 is noise here.
# shellcheck disable=SC2034
{
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
}

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

# P2 additions — new opt-in task flags.
INSTALL_PCIE_GEN3=0
THERMAL_THRESHOLDS_SET=0
TEMP_LIMIT=""
TEMP_SOFT_LIMIT=""
INITIAL_TURBO=""
REQUEST_UNDERCLOCK=0
WIFI_POWERSAVE_OFF=0
DISABLE_BLUETOOTH=0
ENABLE_DNS_CACHE=0
INSTALL_WIREGUARD=0
ALLOW_BOTH_VPN=0
INSTALL_NODE_EXPORTER=0
INSTALL_SMARTMONTOOLS=0
INSTALL_CLI_MODERN=0
INSTALL_NET_DIAG=0
DOCKER_BUILDX_MULTIARCH=0
DOCKER_CGROUPV2=0

# P3 additions — framework features.
PI_OUTPUT_JSON=0
PI_NON_INTERACTIVE=0
PI_PROFILE=""
PI_REPORT=0
PI_SNAPSHOT_ONLY=0
PI_RESTORE_PATH=""
PI_UNDO_TASK=""

# P4 additions — installed-layout maintenance flags.
PI_UNINSTALL=0
PI_MIGRATE_INSTALL=0
PI_ROLLBACK=0
# shellcheck disable=SC2034  # read by lib/features/install.sh
PI_PREFIX="${PI_OPTIMISER_PREFIX:-/opt/pi-optimiser}"

# P5 additions — self-update + TUI.
PI_DO_UPDATE=0
PI_DO_CHECK_UPDATE=0
PI_UPDATE_TIMER_ENABLE=0
PI_UPDATE_TIMER_DISABLE=0
# shellcheck disable=SC2034  # read by lib/features/update.sh
PI_REQUIRE_SIGNATURE=0
PI_FORCE_TUI=0
PI_NO_TUI=0
PI_CONFIG_FILE=""
PI_NO_CONFIG=0
PI_LIST_PROFILES=0
PI_VALIDATE_CONFIG_PATH=""
PI_COMPLETION_SHELL=""
PI_SHOW_CONFIG=0
PI_UNDO_ALL=0
PI_REBOOT_AFTER=""
PI_SELF_TEST=0

# P7 additions (9.2.0) — headless-hardening + Geerling/NVMe tweaks.
POWER_OFF_HALT=0
INSTALL_FIREWALL=0
NVME_TUNE=0
QUIET_BOOT=0
DISABLE_LEDS=0
INSTALL_PI_CONNECT=0
REMOVE_CUPS=0
HEADLESS_GPU_MEM=0
INSTALL_CHRONY=0
DISABLE_IPV6=0
USB_UAS_QUIRKS=0
USB_UAS_EXTRA=""
INSTALL_HAILO=0

# P6 additions — metrics, watch mode, per-task freeze, diff-preview.
# shellcheck disable=SC2034  # read by lib/features/metrics.sh
PI_METRICS_ENABLED=1
# shellcheck disable=SC2034  # read by lib/features/metrics.sh
PI_METRICS_PATH=""
PI_WATCH=0
# shellcheck disable=SC2034  # populated from config.yaml freeze_tasks
declare -A PI_FROZEN_TASKS=()
# shellcheck disable=SC2034  # toggled by --diff; read by config_txt/cmdline helpers
PI_CONFIG_PREVIEW=0
PI_DIFF_MODE=0
# shellcheck disable=SC2034  # buffer directory used by config-preview helpers
PI_CONFIG_PREVIEW_DIR=""

# shellcheck disable=SC2034  # used by lib/util/* modules
APT_UPDATED=0
CURRENT_TASK=""
# shellcheck disable=SC2034
OS_ID=""
# shellcheck disable=SC2034
OS_ID_LIKE=""
# shellcheck disable=SC2034
OS_CODENAME=""

# shellcheck disable=SC2034
SYSTEM_MODEL=""
# shellcheck disable=SC2034
SYSTEM_PI_GEN=""
# shellcheck disable=SC2034
SYSTEM_RAM_MB=0
# shellcheck disable=SC2034
SYSTEM_BOOT_DEVICE=""
# shellcheck disable=SC2034
SYSTEM_KERNEL=""
# shellcheck disable=SC2034
SYSTEM_FIRMWARE=""
# shellcheck disable=SC2034
SYSTEM_ARCH=""

declare -a PRECHECK_WARNINGS=()
declare -a PRECHECK_BLOCKERS=()
POWER_HEALTHY=1
# shellcheck disable=SC2034  # read by lib/util/apt.sh and many tasks
NETWORK_AVAILABLE=1

# shellcheck disable=SC2034  # consumed by lib/util/backup.sh
declare -A BACKED_UP=()
declare -A SKIP_TASKS=()
declare -a ONLY_TASKS=()
declare -a SUMMARY_COMPLETED=()
declare -a SUMMARY_SKIPPED=()
declare -a SUMMARY_FAILED=()

# ---- Task registry ---------------------------------------------------
# Each lib/tasks/<id>.sh calls pi_task_register with its metadata.
# PI_TASK_FLAGS / GATE_FLAG / GATE_VAR / DEFAULT are recorded for P3+
# features (--profile, --report, TUI preselection) and aren't consumed
# by the main loop today; shellcheck can't see cross-file reads.
# shellcheck disable=SC2034
declare -A PI_TASK_DESC=() PI_TASK_CATEGORY=() PI_TASK_VERSION=() \
          PI_TASK_FLAGS=() PI_TASK_POWER_SENSITIVE=() PI_TASK_DEFAULT=() \
          PI_TASK_GATE_FLAG=() PI_TASK_GATE_VAR=() PI_TASK_SKIP_VAR=() \
          PI_TASK_REBOOT_REQUIRED=() PI_TASK_RUNNER=()
declare -a PI_TASK_ORDER=()

TASK_SKIP_REASON=""

TASK_STATE_STATUS=""
TASK_STATE_TIMESTAMP=""
TASK_STATE_DESC=""
TASK_STATE_VERSION=""

# Register a task with metadata. Usage:
#   pi_task_register <id> key=value [key=value ...]
# Recognised keys: description, category, version, flags, gate_flag,
# gate_var, default_enabled, power_sensitive. Unknown keys are ignored
# so newer tasks on older framework versions degrade gracefully.
# shellcheck disable=SC2034
pi_task_register() {
  local id=$1
  shift
  # A second registration for the same id would silently override the
  # first — a paste error in lib/tasks/ could break a task without
  # anything tripping. Warn so the conflict is visible.
  if [[ -n "${PI_TASK_DESC[$id]:-}" ]]; then
    echo "pi-optimiser: duplicate task registration for '$id'; later definition wins" >&2
  fi
  PI_TASK_DESC[$id]="unknown"
  PI_TASK_CATEGORY[$id]="unknown"
  PI_TASK_VERSION[$id]="1.0.0"
  PI_TASK_FLAGS[$id]=""
  PI_TASK_GATE_FLAG[$id]=""
  PI_TASK_GATE_VAR[$id]=""
  PI_TASK_DEFAULT[$id]="1"
  PI_TASK_POWER_SENSITIVE[$id]="0"
  PI_TASK_RUNNER[$id]="run_$id"
  local arg key value
  for arg in "$@"; do
    key=${arg%%=*}
    value=${arg#*=}
    case $key in
      description)     PI_TASK_DESC[$id]=$value ;;
      category)        PI_TASK_CATEGORY[$id]=$value ;;
      version)         PI_TASK_VERSION[$id]=$value ;;
      flags)           PI_TASK_FLAGS[$id]=$value ;;
      gate_flag)       PI_TASK_GATE_FLAG[$id]=$value ;;
      gate_var)        PI_TASK_GATE_VAR[$id]=$value ;;
      skip_var)        PI_TASK_SKIP_VAR[$id]=$value ;;
      reboot_required) PI_TASK_REBOOT_REQUIRED[$id]=$value ;;
      default_enabled) PI_TASK_DEFAULT[$id]=$value ;;
      power_sensitive) PI_TASK_POWER_SENSITIVE[$id]=$value ;;
      runner)          PI_TASK_RUNNER[$id]=$value ;;
    esac
  done
}

# Record a skip reason for the current task. Caller must `return 2`.
pi_skip_reason() {
  TASK_SKIP_REASON="$CURRENT_TASK ($*)"
}

# Source every lib/tasks/*.sh in sorted order; each file self-registers.
# A file is treated as a task only if it contains a `pi_task_register`
# call — stray scripts dropped in the directory by hand or by a sloppy
# rsync won't be re-executed (they'd re-enter main and exit 1).
pi_load_tasks() {
  local tasks_dir="$SCRIPT_DIR/lib/tasks"
  if [[ ! -d "$tasks_dir" ]]; then
    echo "pi-optimiser: missing task directory $tasks_dir" >&2
    exit 1
  fi
  local _task_file
  for _task_file in "$tasks_dir"/*.sh; do
    [[ -f "$_task_file" ]] || continue
    if ! grep -q '^[[:space:]]*pi_task_register[[:space:]]' "$_task_file"; then
      log_warn "Skipping $_task_file (no pi_task_register call found)"
      continue
    fi
    # shellcheck source=/dev/null
    source "$_task_file"
  done
}

# Load lib/MANIFEST and populate PI_TASK_ORDER. Strict on missing task
# files; lenient on registered tasks absent from the manifest (appends
# them at the end so drop-in task files still run).
pi_load_manifest() {
  local manifest="$SCRIPT_DIR/lib/MANIFEST"
  PI_TASK_ORDER=()
  if [[ ! -f "$manifest" ]]; then
    echo "pi-optimiser: missing lib/MANIFEST" >&2
    exit 1
  fi
  local line id
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%%#*}
    line=${line//[[:space:]]/}
    [[ -z "$line" ]] && continue
    if [[ -z "${PI_TASK_DESC[$line]:-}" ]]; then
      echo "pi-optimiser: MANIFEST lists '$line' but no task of that id is registered" >&2
      exit 1
    fi
    PI_TASK_ORDER+=("$line")
  done < "$manifest"
  for id in "${!PI_TASK_DESC[@]}"; do
    if ! printf '%s\n' "${PI_TASK_ORDER[@]}" | grep -qx "$id"; then
      log_warn "Task '$id' registered but missing from MANIFEST; appending to end"
      PI_TASK_ORDER+=("$id")
    fi
  done
}

# Print command usage information.
usage() {
  # When $0 starts with `./` the user invoked a checkout directly, so
  # keep the `./` prefix in the usage line. An absolute path (launcher
  # symlink, e.g. /usr/local/sbin/pi-optimiser) or a bare name means
  # pi-optimiser is installed — display just the command name.
  local invoke
  if [[ "$0" == ./* ]]; then
    invoke="./$SCRIPT_NAME"
  else
    invoke="$SCRIPT_NAME"
  fi
  cat <<USAGE
Usage: sudo $invoke [options]

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
  --pcie-gen3            Enable Pi 5 PCIe Gen 3 (dtparam=pciex1_gen=3)
  --temp-limit <C>       Set firmware temp_limit (°C)
  --temp-soft-limit <C>  Set firmware temp_soft_limit (°C)
  --initial-turbo <sec>  Set firmware initial_turbo window (seconds)
  --underclock           Apply low-power underclock profile (conflicts with OC)
  --wifi-powersave-off   Disable Wi-Fi power save via systemd helper
  --disable-bluetooth    Disable and mask Bluetooth stack + overlay
  --enable-dns-cache     Enable systemd-resolved stub DNS cache
  --install-wireguard    Install wireguard-tools (mutex with Tailscale)
  --allow-both-vpn       Allow Tailscale + WireGuard together
  --install-node-exporter  Install prometheus-node-exporter on :9100
  --install-smartmontools  Install smartmontools + enable smartd
  --install-cli-modern   Install modern CLI bundle (ncdu/ripgrep/fd/bat/nvim)
  --install-net-diag     Install network diagnostics (nmap/iperf3/tcpdump)
  --docker-buildx-multiarch  Install qemu-user-static + seed binfmt for buildx
  --docker-cgroupv2      Append systemd.unified_cgroup_hierarchy=1 to cmdline
  --install-firewall     Install and enable UFW (deny-in, allow SSH + VPN meshes)
  --power-off-halt       Pi 5: cut 3V3 on shutdown (~0.01 W idle; disable if HATs use 3V3)
  --nvme-tune            Disable NVMe APST for compatibility with some Pi 5 NVMe HATs
  --quiet-boot           Hide the rainbow splash and silence kernel log at boot
  --disable-leds         Turn off activity/power/ethernet LEDs (headless/rack)
  --install-pi-connect   Install Raspberry Pi Connect (browser-based remote access)
  --remove-cups          Purge CUPS/printer packages (auto on kiosk/server/headless-iot)
  --headless-gpu-mem     Pi <=4: shrink GPU mem split to 16 MB for headless (Pi 5 ignored)
  --install-chrony       Replace systemd-timesyncd with chrony (flaky-network devices)
  --disable-ipv6         Disable IPv6 via sysctl (leaves a restorable drop-in)
  --usb-uas-quirks       Auto-detect known-bad USB-SATA adapters and disable UAS
  --usb-uas-extra <list> Extra VID:PID pairs for UAS quirks (comma-separated)
  --install-hailo        Pi 5: install Hailo NPU drivers for the AI Kit / AI HAT+
  --profile <name>       Apply flag bundle: kiosk | server | desktop | headless-iot
  --report               Print a human-readable state report and exit
  --snapshot             Tar key config files to /etc/pi-optimiser/snapshots and exit
  --restore <path>       Restore a snapshot tarball and exit
  --undo <task>          Restore files changed during the last run of <task>
  --output <fmt>         Output format: text (default) or json
  --yes, -y              Non-interactive mode; assume yes to any future prompts
  --non-interactive      Alias of --yes
  --uninstall            Remove /opt/pi-optimiser install tree and launcher symlink
  --migrate              Copy this checkout into /opt/pi-optimiser and symlink the launcher
  --rollback             Flip /opt/pi-optimiser/current to the previous release
  --update               Self-update from the GitHub repo (master, unless PI_OPTIMISER_REF set)
  --check-update         Show whether a newer commit exists on the tracking ref
  --require-signature    Abort --update unless the release tarball carries a valid minisign signature
  --enable-update-timer  Install a daily systemd timer that runs --update --yes
  --disable-update-timer Remove the update timer and service unit
  --tui                  Launch the interactive whiptail menu (default on a TTY with no action flags)
  --no-tui               Suppress the interactive menu even on a TTY
  --config <path>        Read a YAML config file; CLI flags still override individual keys
  --no-config            Ignore /etc/pi-optimiser/config.yaml even if present
  --list-profiles        Print the built-in profiles and what they enable, then exit
  --validate-config <p>  Check a config.yaml for parse errors, then exit (no side effects)
  --completion <shell>   Emit a completion script for {bash,zsh} on stdout and exit
  --show-config          Print the effective config (CLI + YAML + defaults) and exit
  --undo --all           Roll back every task completed in the most recent run
  --self-test            Run every task's preconditions read-only and report results
  --reboot-after <mins>  Reboot the Pi <mins> minutes after a successful run
  --keep-screen-blanking Keep default desktop blanking behaviour
  --watch                Re-run on config.yaml changes (requires inotify-tools)
  --no-metrics           Skip writing Prometheus textfile-collector metrics
  --metrics-path <path>  Override Prometheus metrics output path
  --diff                 Preview proposed config.txt/cmdline.txt changes without writing
  --freeze-task <id>     Treat <id> as completed even if its version bumps (repeatable)
  --help                 Show this help message and exit
  --version              Print script version and exit

Tasks can be referenced by their short name shown with --list-tasks or --status.
USAGE
}

# Source shared utility modules from lib/util/. The main script resolves
# its own location so it can be invoked via symlink (e.g. the launcher
# at /usr/local/sbin/pi-optimiser) or absolute path. readlink -f chases
# the symlink to the real release tree under /opt/pi-optimiser/.
_pi_self=${BASH_SOURCE[0]}
if command -v readlink >/dev/null 2>&1; then
  _resolved=$(readlink -f "$_pi_self" 2>/dev/null || echo "$_pi_self")
else
  _resolved=$_pi_self
fi
SCRIPT_DIR=$(cd "$(dirname "$_resolved")" && pwd)
unset _pi_self _resolved
LIB_UTIL_DIR="$SCRIPT_DIR/lib/util"
if [[ ! -d "$LIB_UTIL_DIR" ]]; then
  echo "pi-optimiser: missing library directory $LIB_UTIL_DIR" >&2
  echo "  Re-download the project or run lib/bootstrap install." >&2
  exit 1
fi
for _util in log python state backup config_txt cmdline fstab sshd apt systemd model hardware preflight validate config_yaml; do
  _util_path="$LIB_UTIL_DIR/${_util}.sh"
  if [[ ! -f "$_util_path" ]]; then
    echo "pi-optimiser: missing utility $_util_path" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source "$_util_path"
done
unset _util _util_path

# Framework features live in lib/features/*.sh. Missing the directory
# is not fatal (older installs) but missing individual files is logged.
LIB_FEATURES_DIR="$SCRIPT_DIR/lib/features"
if [[ -d "$LIB_FEATURES_DIR" ]]; then
  for _feat in profiles report snapshot undo install update completion metrics watch diff; do
    _feat_path="$LIB_FEATURES_DIR/${_feat}.sh"
    if [[ -f "$_feat_path" ]]; then
      # shellcheck source=/dev/null
      source "$_feat_path"
    fi
  done
  unset _feat _feat_path
fi

# UI module — whiptail TUI.
LIB_UI_DIR="$SCRIPT_DIR/lib/ui"
if [[ -f "$LIB_UI_DIR/tui.sh" ]]; then
  # shellcheck source=/dev/null
  source "$LIB_UI_DIR/tui.sh"
fi

# Return previously configured proxy backend from state file.
get_stored_proxy_backend() {
  local backend
  if backend=$(read_json_field "$CONFIG_OPTIMISER_STATE" "proxy.backend" 2>/dev/null); then
    printf '%s\n' "$backend"
    return 0
  fi
  return 1
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

# Run a registered task with idempotent state tracking. Interprets the
# task runner's exit code: 0=done (mark completed), 2=skipped (no state
# change), anything else=failed.
apply_once() {
  local task=$1
  local desc=${PI_TASK_DESC[$task]:-$task}
  local runner=${PI_TASK_RUNNER[$task]:-run_$task}
  CURRENT_TASK="$task"
  TASK_SKIP_REASON=""
  # --freeze-task / config.yaml freeze_tasks: pin a task at its current
  # recorded version. Frozen always wins — over --force, --diff, and
  # --dry-run — since the user explicitly opted out of running this id.
  if [[ -n "${PI_FROZEN_TASKS[$task]:-}" ]]; then
    log_info "Skipping $task (frozen)"
    SUMMARY_SKIPPED+=("$task (frozen)")
    return 0
  fi
  # --diff runs before the already-completed short-circuit because the
  # user wants to see what the current config would do, even for tasks
  # that have already been applied. No state mutation, no real runner.
  if [[ ${PI_CONFIG_PREVIEW:-0} -eq 1 ]]; then
    local _preview_fn="pi_preview_${task}"
    if declare -F "$_preview_fn" >/dev/null 2>&1; then
      "$_preview_fn" || true
      SUMMARY_SKIPPED+=("$task (preview)")
    else
      SUMMARY_SKIPPED+=("$task (no preview available)")
    fi
    return 0
  fi
  if [[ $FORCE -eq 0 ]] && is_task_done "$task"; then
    log_info "Skipping $task (already completed)"
    SUMMARY_SKIPPED+=("$task (already completed)")
    return 0
  fi
  if [[ $FORCE -eq 1 && $DRY_RUN -eq 0 ]]; then
    # Under --dry-run, preserving the existing state is essential —
    # the whole point is that no side effects happen. We still honour
    # --force enough to let the task "run" (below) so dry-run output
    # shows what would happen, but we don't mutate state.json.
    clear_task_state "$task"
  fi
  log_info "Running task $task: $desc"
  if [[ $DRY_RUN -eq 1 ]]; then
    # Consult the task's gate_var/skip_var metadata (set by
    # pi_task_register) so dry-run can tell "opt-in not requested" and
    # "explicitly suppressed" apart from "would actually run".
    local _gate=${PI_TASK_GATE_VAR[$task]:-}
    if [[ -n "$_gate" ]]; then
      local _gate_val="${!_gate:-}"
      if [[ -z "$_gate_val" || "$_gate_val" == "0" ]]; then
        log_info "[dry-run] $task would skip — $_gate is unset"
        SUMMARY_SKIPPED+=("$task (not requested)")
        return 0
      fi
    fi
    local _skip=${PI_TASK_SKIP_VAR[$task]:-}
    if [[ -n "$_skip" ]]; then
      local _skip_val="${!_skip:-}"
      if [[ -n "$_skip_val" && "$_skip_val" != "0" ]]; then
        log_info "[dry-run] $task would skip — $_skip is set"
        SUMMARY_SKIPPED+=("$task (suppressed by $_skip)")
        return 0
      fi
    fi
    log_info "[dry-run] $task would run"
    SUMMARY_SKIPPED+=("$task (dry-run)")
    return 0
  fi
  local rc=0
  "$runner" || rc=$?
  case $rc in
    0)
      set_task_state "$task" "completed" "$desc"
      log_info "Completed task $task"
      SUMMARY_COMPLETED+=("$task")
      # Tasks that edit /boot/firmware/* or firmware/EEPROM flag the
      # run as needing a reboot via the `reboot_required=1` metadata.
      if [[ ${PI_TASK_REBOOT_REQUIRED[$task]:-0} == "1" ]]; then
        pi_mark_reboot_required "$task"
      fi
      ;;
    2)
      local reason=${TASK_SKIP_REASON:-"$task (task skipped)"}
      SUMMARY_SKIPPED+=("$reason")
      ;;
    *)
      set_task_state "$task" "failed" "$desc"
      log_error "Task $task failed (rc=$rc)"
      SUMMARY_FAILED+=("$task")
      return 1
      ;;
  esac
}

# Show current task status table, walking the registry in manifest order.
# The "current" column is the task's version on disk today; "ran" is the
# version that was recorded the last time the task completed. Divergence
# is a hint that the task may want a --force re-run.
print_status() {
  ensure_marker_store
  if [[ ${PI_OUTPUT_JSON:-0} -eq 1 ]]; then
    _print_status_json
    return 0
  fi
  printf '%-18s %-8s %-8s %-12s %-25s %s\n' "TASK" "CURRENT" "RAN" "STATUS" "TIMESTAMP" "DETAILS"
  printf '%-18s %-8s %-8s %-12s %-25s %s\n' "----" "-------" "---" "------" "---------" "-------"
  local task status timestamp details current_v ran_v desc
  for task in "${PI_TASK_ORDER[@]}"; do
    current_v=${PI_TASK_VERSION[$task]:-1.0.0}
    desc=${PI_TASK_DESC[$task]:-}
    if get_task_state "$task"; then
      status="$TASK_STATE_STATUS"
      timestamp="$TASK_STATE_TIMESTAMP"
      details="$TASK_STATE_DESC"
      ran_v=${TASK_STATE_VERSION:-"--"}
    else
      status="pending"
      timestamp="--"
      details="$desc"
      ran_v="--"
    fi
    printf '%-18s %-8s %-8s %-12s %-25s %s\n' \
      "$task" "$current_v" "$ran_v" "$status" "$timestamp" "$details"
  done
}

# JSON variant used when --output json is set.
_print_status_json() {
  STATE_JSON_PATH="$STATE_JSON_FILE" PI_ORDER_LIST="${PI_TASK_ORDER[*]}" run_python <<'PY'
import json, os, sys
state_path = os.environ.get("STATE_JSON_PATH", "")
order = os.environ.get("PI_ORDER_LIST", "").split()
try:
    with open(state_path) as fh:
        state = json.load(fh)
except Exception:
    state = {}
tasks_state = (state.get("tasks") or {})

out = {
    "schema_version": state.get("schema_version", 2),
    "order": order,
    "tasks": [],
}
for tid in order:
    rec = tasks_state.get(tid, {})
    out["tasks"].append({
        "id": tid,
        "status": rec.get("status", "pending"),
        "timestamp": rec.get("timestamp"),
        "task_version_ran": rec.get("task_version"),
        "description": rec.get("description"),
    })
json.dump(out, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
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
  if declare -F pi_reboot_required >/dev/null 2>&1 && pi_reboot_required; then
    log_warn "  >>> REBOOT REQUIRED: one or more tasks changed boot/firmware config <<<"
    log_warn "      Reboot the Pi when convenient for the changes to take effect."
  fi
}

# List all registered tasks in manifest order with their versions.
list_tasks() {
  printf '%-18s %-8s %-20s %s\n' "TASK" "VERSION" "CATEGORY" "DESCRIPTION"
  printf '%-18s %-8s %-20s %s\n' "----" "-------" "--------" "-----------"
  local task
  for task in "${PI_TASK_ORDER[@]}"; do
    printf '%-18s %-8s %-20s %s\n' \
      "$task" \
      "${PI_TASK_VERSION[$task]:-1.0.0}" \
      "${PI_TASK_CATEGORY[$task]:-unknown}" \
      "${PI_TASK_DESC[$task]:-}"
  done
  echo
  echo "Opt-in tasks require their respective --flag (see --help)."
}

# Parse CLI arguments and populate global flags.
# shellcheck disable=SC2034  # globals set here are read by lib/tasks/*.sh
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
      --pcie-gen3)            INSTALL_PCIE_GEN3=1 ;;
      --underclock)           REQUEST_UNDERCLOCK=1 ;;
      --wifi-powersave-off)   WIFI_POWERSAVE_OFF=1 ;;
      --disable-bluetooth)    DISABLE_BLUETOOTH=1 ;;
      --enable-dns-cache)     ENABLE_DNS_CACHE=1 ;;
      --install-wireguard)    INSTALL_WIREGUARD=1 ;;
      --allow-both-vpn)       ALLOW_BOTH_VPN=1 ;;
      --install-node-exporter) INSTALL_NODE_EXPORTER=1 ;;
      --install-smartmontools) INSTALL_SMARTMONTOOLS=1 ;;
      --install-cli-modern)   INSTALL_CLI_MODERN=1 ;;
      --install-net-diag)     INSTALL_NET_DIAG=1 ;;
      --docker-buildx-multiarch) DOCKER_BUILDX_MULTIARCH=1 ;;
      --power-off-halt)      POWER_OFF_HALT=1 ;;
      --install-firewall)    INSTALL_FIREWALL=1 ;;
      --nvme-tune)           NVME_TUNE=1 ;;
      --quiet-boot)          QUIET_BOOT=1 ;;
      --disable-leds)        DISABLE_LEDS=1 ;;
      --install-pi-connect)  INSTALL_PI_CONNECT=1 ;;
      --remove-cups)         REMOVE_CUPS=1 ;;
      --headless-gpu-mem)    HEADLESS_GPU_MEM=1 ;;
      --install-chrony)      INSTALL_CHRONY=1 ;;
      --disable-ipv6)        DISABLE_IPV6=1 ;;
      --usb-uas-quirks)      USB_UAS_QUIRKS=1 ;;
      --usb-uas-extra)
        if [[ $# -lt 2 ]]; then echo "--usb-uas-extra requires a VID:PID[,VID:PID] list" >&2; exit 1; fi
        USB_UAS_EXTRA=$2; USB_UAS_QUIRKS=1; shift
        ;;
      --install-hailo)       INSTALL_HAILO=1 ;;
      --docker-cgroupv2)      DOCKER_CGROUPV2=1 ;;
      --yes|-y|--non-interactive) PI_NON_INTERACTIVE=1 ;;
      --uninstall)           PI_UNINSTALL=1 ;;
      --migrate)             PI_MIGRATE_INSTALL=1 ;;
      --rollback)            PI_ROLLBACK=1 ;;
      --update)              PI_DO_UPDATE=1 ;;
      --check-update)        PI_DO_CHECK_UPDATE=1 ;;
      --require-signature)   PI_REQUIRE_SIGNATURE=1 ;;
      --enable-update-timer) PI_UPDATE_TIMER_ENABLE=1 ;;
      --disable-update-timer) PI_UPDATE_TIMER_DISABLE=1 ;;
      --tui)                 PI_FORCE_TUI=1 ;;
      --no-tui)              PI_NO_TUI=1 ;;
      --config)
        if [[ $# -lt 2 ]]; then echo "--config requires a path" >&2; exit 1; fi
        PI_CONFIG_FILE=$2; shift
        ;;
      --no-config)           PI_NO_CONFIG=1 ;;
      --list-profiles)       PI_LIST_PROFILES=1 ;;
      --validate-config)
        if [[ $# -lt 2 ]]; then echo "--validate-config requires a path" >&2; exit 1; fi
        PI_VALIDATE_CONFIG_PATH=$2; shift
        ;;
      --completion)
        if [[ $# -lt 2 ]]; then echo "--completion requires a shell (bash|zsh)" >&2; exit 1; fi
        PI_COMPLETION_SHELL=$2; shift
        ;;
      --show-config)         PI_SHOW_CONFIG=1 ;;
      --self-test)           PI_SELF_TEST=1 ;;
      --reboot-after)
        if [[ $# -lt 2 ]]; then echo "--reboot-after requires a minute count" >&2; exit 1; fi
        if ! [[ $2 =~ ^[0-9]+$ ]]; then echo "--reboot-after expects an integer (minutes)" >&2; exit 1; fi
        PI_REBOOT_AFTER=$2; shift
        ;;
      --report)               PI_REPORT=1 ;;
      --snapshot)             PI_SNAPSHOT_ONLY=1 ;;
      --restore)
        if [[ $# -lt 2 ]]; then echo "--restore requires a path" >&2; exit 1; fi
        PI_RESTORE_PATH=$2; shift
        ;;
      --undo)
        if [[ $# -lt 2 ]]; then echo "--undo requires a task id or --all" >&2; exit 1; fi
        if [[ "$2" == "--all" ]]; then
          PI_UNDO_ALL=1
        else
          PI_UNDO_TASK=$2
        fi
        shift
        ;;
      --profile)
        if [[ $# -lt 2 ]]; then echo "--profile requires a name" >&2; exit 1; fi
        PI_PROFILE=$2; pi_apply_profile "$2"; shift
        ;;
      --output)
        if [[ $# -lt 2 ]]; then echo "--output requires a format" >&2; exit 1; fi
        case ${2,,} in
          json) PI_OUTPUT_JSON=1 ;;
          text|human) PI_OUTPUT_JSON=0 ;;
          *) echo "Unsupported --output value: $2 (allowed: text, json)" >&2; exit 1 ;;
        esac
        shift
        ;;
      --temp-limit)
        if [[ $# -lt 2 ]]; then echo "--temp-limit requires a value" >&2; exit 1; fi
        TEMP_LIMIT=$2; THERMAL_THRESHOLDS_SET=1; shift
        ;;
      --temp-soft-limit)
        if [[ $# -lt 2 ]]; then echo "--temp-soft-limit requires a value" >&2; exit 1; fi
        TEMP_SOFT_LIMIT=$2; THERMAL_THRESHOLDS_SET=1; shift
        ;;
      --initial-turbo)
        if [[ $# -lt 2 ]]; then echo "--initial-turbo requires a value" >&2; exit 1; fi
        INITIAL_TURBO=$2; THERMAL_THRESHOLDS_SET=1; shift
        ;;
      --keep-screen-blanking)
        KEEP_SCREEN_BLANKING=1
        ;;
      --watch)
        PI_WATCH=1
        ;;
      --no-metrics)
        PI_METRICS_ENABLED=0
        ;;
      --metrics-path)
        if [[ $# -lt 2 ]]; then echo "--metrics-path requires a path" >&2; exit 1; fi
        PI_METRICS_PATH=$2; shift
        ;;
      --diff)
        PI_DIFF_MODE=1; PI_CONFIG_PREVIEW=1
        ;;
      --freeze-task)
        if [[ $# -lt 2 ]]; then echo "--freeze-task requires a task id" >&2; exit 1; fi
        if ! [[ $2 =~ ^[a-z0-9_]+$ ]]; then echo "--freeze-task '$2' is not a valid task id" >&2; exit 1; fi
        PI_FROZEN_TASKS[$2]=1; shift
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

  pi_validate_mutex || exit 1
}

# Check mutually-exclusive gate-var combinations. Emits a human-readable
# error on each conflict found, returning 0 when state is coherent and
# 1 otherwise. Called from three paths:
#   - parse_args (CLI flags path — exit 1 on failure)
#   - main() after config.yaml load (YAML path — exit 1 on failure)
#   - _pi_tui_apply (interactive path — re-opens the menu on failure)
# Keep every genuine mutex in here so the three paths stay aligned.
pi_validate_mutex() {
  local rc=0

  # OC vs underclock — both edit arm_freq / gpu_freq in config.txt;
  # applying both leaves the outcome order-dependent.
  if [[ ${REQUEST_OC_CONSERVATIVE:-0} -eq 1 && ${REQUEST_UNDERCLOCK:-0} -eq 1 ]]; then
    echo "pi-optimiser: overclock-conservative and underclock conflict." >&2
    echo "  Pick one; they set opposing arm_freq / gpu_freq values." >&2
    rc=1
  fi

  # Tailscale vs WireGuard — both install a default VPN route and
  # fight over /etc/resolv.conf on some distros. Allow the combo only
  # when the operator explicitly opts in with --allow-both-vpn.
  if [[ ${INSTALL_TAILSCALE:-0} -eq 1 && ${INSTALL_WIREGUARD:-0} -eq 1 && ${ALLOW_BOTH_VPN:-0} -eq 0 ]]; then
    echo "pi-optimiser: tailscale and wireguard both selected." >&2
    echo "  Pass --allow-both-vpn (CLI) or set allow_both_vpn in config.yaml to run both." >&2
    rc=1
  fi

  # CPU governor=performance pinning vs underclock — philosophically
  # contradictory (the service pins to 'performance' while underclock
  # flips the live governor to 'powersave' on apply). The underclock
  # task already backs off when OC is requested; here we warn softly
  # rather than block, since the user may want the kernel governor
  # pinned even with a lower ceiling.
  if [[ ${REQUEST_UNDERCLOCK:-0} -eq 1 ]]; then
    :  # Reserved: future soft warning hook.
  fi

  # ZRAM install + zram-algo=disabled — not strictly conflicting (the
  # disabled branch wins and tears down zram-generator.conf) but worth
  # a warning so the user isn't surprised.
  if [[ ${INSTALL_ZRAM:-0} -eq 1 && "${ZRAM_ALGO_OVERRIDE:-}" == "disabled" ]]; then
    echo "pi-optimiser: install-zram + zram-algo=disabled — the 'disabled' branch wins." >&2
    echo "  Drop install-zram to tear ZRAM down, or drop zram-algo=disabled to install." >&2
    # Soft conflict: don't raise rc.
  fi

  return $rc
}

# Return success when the given task is flagged power-sensitive in the
# registry. Consumed by the main loop to gate tasks behind a healthy
# vcgencmd/throttle preflight.
is_power_sensitive_task() {
  [[ ${PI_TASK_POWER_SENSITIVE[$1]:-0} == "1" ]]
}

# Compute ZRAM size based on RAM tier with sensible caps.

# Purge optional desktop software and clean apt caches.

# Apply noatime and commit adjustments to root filesystem entry.

# Disable legacy swapfile service and ensure swap is off.

# Select preferred ZRAM compression algorithm (default lz4).

# Configure or disable systemd zram generator with sized swap device.

# Keep systemd journal in RAM with modest size limits.

# Apply kernel tuning for memory, file limits, and networking.

# Harden apt behaviour and disable automatic background jobs.


# Configure security-only unattended upgrades on a timer.

# Ensure essential command-line utilities are installed.

# Set system locale when requested via --locale flag.


# Manage nginx reverse proxy configuration and lifecycle.
# Raise system and user ulimit defaults for file descriptors/processes.

# Disable non-essential background services for kiosk workloads.

# Configure Tailscale repository and install client when requested.

# Install Docker Engine (upstream if possible) and enable service.

# Turn off console and desktop blanking/DPMS for kiosk screens.


# Relocate /var/log to tmpfs with supporting tmpfiles rules.


# Apply vc4 KMS display defaults when supported by hardware.

# Ensure vc4 overlays disable liftoff to prevent compositor glitches.


# Apply vendor-safe CPU/GPU overclock profiles for Pi 5/500/4/400/3/Zero 2.


# Harden sshd configuration and enable fail2ban protection.


# Install systemd service that pins the CPU scaling governor to performance.


# Apply SDRAM_BANKLOW tuning to the Raspberry Pi bootloader EEPROM.


# Install latest Raspberry Pi firmware via rpi-update (opt-in, non-interactive).


# Enable fstrim.timer for periodic TRIM on SSD/NVMe/eMMC roots.


# Set the system timezone when requested via --timezone.


# Set the system hostname when requested via --hostname.


# Import authorized_keys from a GitHub user and/or arbitrary HTTPS URL.


# Enable the Raspberry Pi hardware watchdog and wire systemd to feed it.


# Apply a Pi 5 PWM fan curve to config.txt (temperatures in millidegrees).


# Refresh the Raspberry Pi bootloader EEPROM via rpi-eeprom-update.


# Ensure /tmp lives on tmpfs to reduce SD card writes.

# Entry point orchestrating argument parsing and task execution.
main() {
  # Tag every backup emitted by this run with a single stamp so --undo
  # can group them. Exported so run_python children see it.
  PI_RUN_STAMP=$(date -Iseconds)
  export PI_RUN_STAMP

  # Remember the original argv so --watch can strip itself and re-exec
  # with the same downstream flags.
  # shellcheck disable=SC2034  # read by lib/features/watch.sh
  PI_WATCH_ARGV=("$@")

  # Capture argv for the TUI gate check (skip the menu when any action
  # flag is explicitly passed).
  # shellcheck disable=SC2034  # read by lib/ui/tui.sh::pi_tui_should_launch
  PI_ARGV_RAW=" $* "
  # Flags that clearly mean "don't show the menu."
  # shellcheck disable=SC2034
  PI_CLI_ACTION_FLAGS=(
    --force --dry-run --status --list-tasks --report --snapshot --restore
    --undo --update --check-update --enable-update-timer
    --disable-update-timer --uninstall --migrate --rollback
    --only --skip
    --install-tailscale --install-docker --install-zram --install-wireguard
    --install-node-exporter --install-smartmontools --install-cli-modern
    --install-net-diag --enable-dns-cache
    --overclock-conservative --underclock --pi5-fan-profile --pcie-gen3
    --enable-watchdog --secure-ssh --firmware-update --eeprom-update
    --install-firewall --power-off-halt --nvme-tune --quiet-boot
    --disable-leds --install-pi-connect --remove-cups
    --headless-gpu-mem --install-chrony --disable-ipv6
    --usb-uas-quirks --usb-uas-extra --install-hailo
    --ssh-import-github --ssh-import-url
    --hostname --timezone --locale --proxy-backend
    --profile --config
  )

  # Pre-scan argv for flags that change config-load decisions. We need
  # to know these BEFORE parse_args so the saved config loads first
  # (giving CLI flags the final say) and info-only commands skip it
  # entirely. This is a deliberately lax scan — parse_args does the
  # strict validation shortly after.
  local _pi_info_only=0 _pi_no_config_early=0 _pi_cfg_path_early=""
  local _arg _prev=""
  for _arg in "$@"; do
    if [[ "$_prev" == "--config" ]]; then
      _pi_cfg_path_early=$_arg
      _prev=""
      continue
    fi
    if [[ "$_prev" == "--validate-config" || "$_prev" == "--completion" ]]; then
      _prev=""
      continue
    fi
    # Pre-set PI_OUTPUT_JSON so the config-load log line routes to
    # stderr instead of polluting a JSON stdout stream.
    if [[ "$_prev" == "--output" ]]; then
      case "${_arg,,}" in json) PI_OUTPUT_JSON=1 ;; esac
      _prev=""
      continue
    fi
    case "$_arg" in
      --help|-h|--version|--list-tasks|--list-profiles|--validate-config|--completion)
        _pi_info_only=1
        [[ "$_arg" == "--validate-config" ]] && _prev=--validate-config
        [[ "$_arg" == "--completion" ]] && _prev=--completion
        ;;
      --show-config)
        # --show-config wants config.yaml loaded so the output reflects
        # reality. It still exits before require_root / state-setup, so
        # no root privileges are needed.
        ;;
      --no-config)  _pi_no_config_early=1 ;;
      --config)     _prev=--config ;;
      --output)     _prev=--output ;;
    esac
  done
  unset _arg _prev

  # Load persisted config BEFORE parse_args so CLI flags win. Skipped
  # entirely for info-only commands (--help, --version, --list-tasks)
  # and when --no-config is passed.
  if [[ $_pi_info_only -eq 0 && $_pi_no_config_early -eq 0 ]]; then
    if [[ -n "$_pi_cfg_path_early" ]]; then
      pi_config_load "$_pi_cfg_path_early" || true
    elif [[ -f "${PI_CONFIG_DEFAULT:-/etc/pi-optimiser/config.yaml}" ]]; then
      pi_config_load "$PI_CONFIG_DEFAULT" || true
    fi
  fi

  parse_args "$@"

  # Tasks must be sourced before --list-tasks so the registry is populated.
  pi_load_tasks
  pi_load_manifest

  # --freeze-task takes a task id, but at parse_args time the registry
  # is empty so we can't validate. Do it now — fail loud on typos
  # instead of silently accepting them.
  if (( ${#PI_FROZEN_TASKS[@]} > 0 )); then
    local _fid
    for _fid in "${!PI_FROZEN_TASKS[@]}"; do
      if [[ -z "${PI_TASK_DESC[$_fid]:-}" ]]; then
        echo "pi-optimiser: --freeze-task '$_fid' is not a registered task id" >&2
        exit 1
      fi
    done
  fi

  if [[ $LIST_TASKS -eq 1 ]]; then
    list_tasks
    exit 0
  fi
  # --list-profiles and --validate-config are info-only too; handle them
  # before state setup so non-root users can introspect without sudo.
  if [[ $PI_LIST_PROFILES -eq 1 ]]; then
    if declare -F pi_list_profiles >/dev/null 2>&1; then
      pi_list_profiles
    else
      echo "pi-optimiser: lib/features/profiles.sh missing pi_list_profiles" >&2
      exit 1
    fi
    exit 0
  fi
  if [[ -n "$PI_VALIDATE_CONFIG_PATH" ]]; then
    if declare -F pi_validate_config >/dev/null 2>&1; then
      local _rc=0
      pi_validate_config "$PI_VALIDATE_CONFIG_PATH" || _rc=$?
      exit $_rc
    fi
    echo "pi-optimiser: lib/features/profiles.sh missing pi_validate_config" >&2
    exit 1
  fi
  if [[ -n "$PI_COMPLETION_SHELL" ]]; then
    case "${PI_COMPLETION_SHELL,,}" in
      bash) pi_emit_completion_bash ;;
      zsh)  pi_emit_completion_zsh ;;
      *) echo "pi-optimiser: unsupported shell '$PI_COMPLETION_SHELL' (expected bash|zsh)" >&2; exit 1 ;;
    esac
    exit 0
  fi
  if [[ $PI_SHOW_CONFIG -eq 1 ]]; then
    if declare -F pi_show_effective_config >/dev/null 2>&1; then
      local _rc=0
      pi_show_effective_config || _rc=$?
      exit $_rc
    fi
    echo "pi-optimiser: lib/features/profiles.sh missing pi_show_effective_config" >&2
    exit 1
  fi

  require_root
  init_logging

  # Serialize concurrent runs (human + update-timer race) under a
  # flock. Two mutating invocations would otherwise race on state.json
  # and the backup journal. --status, --report, --list-tasks,
  # --check-update are read-only paths; those are checked later and
  # exit without acquiring the lock. We acquire as early as possible
  # once we're committed to any side-effecting action.
  if command -v flock >/dev/null 2>&1; then
    # shellcheck disable=SC2094  # fd 9 is our lock fd
    exec 9>/var/lock/pi-optimiser.lock
    if ! flock -n 9; then
      log_error "Another pi-optimiser run is in progress (/var/lock/pi-optimiser.lock held)."
      log_error "If you're sure that's stale, delete it or wait for the other run."
      exit 1
    fi
  fi

  trap 'on_err $? $LINENO' ERR
  ensure_marker_store
  load_os_release
  gather_system_info
  arch_sanity_banner
  preflight_checks
  if [[ $STATUS_ONLY -eq 1 ]]; then
    print_status
    exit 0
  fi
  if [[ $PI_REPORT -eq 1 ]]; then
    pi_generate_report
    exit 0
  fi
  # `set -e` + ERR trap would log a misleading "Failure at line …" for
  # a feature that legitimately returns non-zero (e.g. --undo against
  # a task that never ran). Use _run_feature to exit cleanly with the
  # feature's return code without tripping the trap.
  local _rc=0
  if [[ $PI_SNAPSHOT_ONLY -eq 1 ]]; then
    pi_take_snapshot || _rc=$?
    exit $_rc
  fi
  if [[ -n "$PI_RESTORE_PATH" ]]; then
    pi_restore_snapshot "$PI_RESTORE_PATH" || _rc=$?
    exit $_rc
  fi
  if [[ -n "$PI_UNDO_TASK" ]]; then
    pi_undo_task "$PI_UNDO_TASK" || _rc=$?
    exit $_rc
  fi
  if [[ $PI_UNDO_ALL -eq 1 ]]; then
    if declare -F pi_undo_all >/dev/null 2>&1; then
      pi_undo_all || _rc=$?
      exit $_rc
    fi
    echo "pi-optimiser: lib/features/undo.sh missing pi_undo_all" >&2
    exit 1
  fi
  if [[ $PI_UNINSTALL -eq 1 ]]; then
    pi_uninstall || _rc=$?
    exit $_rc
  fi
  if [[ $PI_MIGRATE_INSTALL -eq 1 ]]; then
    pi_migrate_install || _rc=$?
    exit $_rc
  fi
  if [[ $PI_ROLLBACK -eq 1 ]]; then
    pi_rollback_release || _rc=$?
    exit $_rc
  fi
  if [[ $PI_UPDATE_TIMER_ENABLE -eq 1 ]]; then
    pi_enable_update_timer || _rc=$?
    exit $_rc
  fi
  if [[ $PI_UPDATE_TIMER_DISABLE -eq 1 ]]; then
    pi_disable_update_timer || _rc=$?
    exit $_rc
  fi
  if [[ $PI_DO_CHECK_UPDATE -eq 1 ]]; then
    pi_check_update || _rc=$?
    exit $_rc
  fi
  if [[ $PI_DO_UPDATE -eq 1 ]]; then
    pi_self_update || _rc=$?
    exit $_rc
  fi
  if [[ $PI_SELF_TEST -eq 1 ]]; then
    if declare -F pi_self_test >/dev/null 2>&1; then
      pi_self_test || _rc=$?
      exit $_rc
    fi
    echo "pi-optimiser: lib/features/profiles.sh missing pi_self_test" >&2
    exit 1
  fi

  # Launch the TUI when appropriate. It populates PI_TUI_SELECTED and
  # the flag globals, then hands control back to the task loop below.
  if declare -F pi_tui_should_launch >/dev/null 2>&1 && pi_tui_should_launch; then
    if declare -F pi_tui_main >/dev/null 2>&1; then
      if ! pi_tui_main; then
        log_info "TUI exited without applying; nothing to do"
        exit 0
      fi
    fi
  fi
  log_info "Starting pi-optimiser version $SCRIPT_VERSION (${#PI_TASK_ORDER[@]} tasks registered)"

  local task
  for task in "${PI_TASK_ORDER[@]}"; do
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
    # Proxy special case: if the backend URL changed since last run,
    # drop the completion marker so the task re-configures nginx.
    if [[ "$task" == "proxy" && -n "$PROXY_BACKEND" ]]; then
      local current_backend
      if current_backend=$(get_stored_proxy_backend); then
        if [[ "$current_backend" != "$PROXY_BACKEND" ]]; then
          log_info "Proxy backend changed from '$current_backend' to '$PROXY_BACKEND'; re-running"
          clear_task_state "$task"
        fi
      else
        clear_task_state "$task"
      fi
    fi
    # ufw_firewall special case: reconcile when the set of things it
    # opens ports for (VPN interfaces, proxy symlink, SSH port) has
    # changed since the last run. Without this the firewall can
    # silently drift when a VPN is added or removed later.
    if [[ "$task" == "ufw_firewall" && ${INSTALL_FIREWALL:-0} -eq 1 ]] \
       && declare -F _ufw_fingerprint >/dev/null 2>&1; then
      local current_fp stored_fp
      current_fp=$(_ufw_fingerprint)
      stored_fp=$(read_json_field "$CONFIG_OPTIMISER_STATE" "firewall.fingerprint" 2>/dev/null || echo "")
      if [[ -n "$stored_fp" && "$stored_fp" != "$current_fp" ]]; then
        log_info "Firewall inputs changed ($stored_fp -> $current_fp); re-reconciling"
        clear_task_state "$task"
      fi
    fi
    # apply_once returns non-zero on fatal task failure. Under `set -e`
    # that kills the loop immediately and skips every remaining task.
    # Capture the rc, keep going, and surface the failure at the end.
    apply_once "$task" || true
  done
  print_run_summary
  if [[ $PI_DIFF_MODE -eq 1 ]] && declare -F pi_diff_flush >/dev/null 2>&1; then
    pi_diff_flush
  fi
  if declare -F pi_metrics_write >/dev/null 2>&1; then
    pi_metrics_write || true
  fi
  log_info "Optimisation run complete"

  # Optional post-run auto-reboot (--reboot-after <mins>). Only when
  # the run completed with no failures and a reboot is actually needed
  # — there's no point rebooting for a run of `--only cpu_governor`.
  if [[ -n "$PI_REBOOT_AFTER" && ${#SUMMARY_FAILED[@]} -eq 0 ]]; then
    if declare -F pi_reboot_required >/dev/null 2>&1 && pi_reboot_required; then
      log_warn "--reboot-after: scheduling reboot in $PI_REBOOT_AFTER minute(s)"
      if ! shutdown -r "+$PI_REBOOT_AFTER" "pi-optimiser --reboot-after $PI_REBOOT_AFTER" >/dev/null 2>&1; then
        log_warn "shutdown(1) failed; not rebooting"
      fi
    else
      log_info "--reboot-after set but no task flagged reboot-required; skipping"
    fi
  fi

  # --watch: parent drops the flock (fd 9) before blocking on inotify
  # so child re-runs can acquire their own lock. Task failures in the
  # first pass don't kill the watcher — the user can fix config.yaml
  # and save to trigger a retry.
  local _enter_watch=0
  if [[ "${PI_WATCH:-0}" == "1" ]] && declare -F pi_watch_loop >/dev/null 2>&1; then
    _enter_watch=1
  fi
  if (( ${#SUMMARY_FAILED[@]} > 0 )); then
    if [[ $_enter_watch -eq 1 ]]; then
      SUMMARY_COMPLETED=() SUMMARY_SKIPPED=() SUMMARY_FAILED=()
      exec 9>&- 2>/dev/null || true
      pi_watch_loop || true
      return 0
    fi
    exit 1
  fi
  if [[ $_enter_watch -eq 1 ]]; then
    exec 9>&- 2>/dev/null || true
    pi_watch_loop || true
  fi
}

main "$@"
