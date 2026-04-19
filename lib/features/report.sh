# ======================================================================
# lib/features/report.sh — human-readable state report
#
# Functions: pi_generate_report
#
# Called when --report is passed. Dumps a current-state overview
# covering hardware, runtime tuning, disk usage, task history. Honours
# --output json.
# ======================================================================

pi_generate_report() {
  if [[ ${PI_OUTPUT_JSON:-0} -eq 1 ]]; then
    _pi_generate_report_json
    return $?
  fi
  _pi_generate_report_text
}

_pi_generate_report_text() {
  local divider="------------------------------------------------------------"
  echo "pi-optimiser — Current State ($(date '+%Y-%m-%d %H:%M'))"
  echo "$divider"
  echo "System"
  printf '  %-16s %s\n' "Model"       "${SYSTEM_MODEL:-unknown}"
  printf '  %-16s %s\n' "Pi gen"      "${SYSTEM_PI_GEN:-unknown}"
  printf '  %-16s %s\n' "Kernel"      "${SYSTEM_KERNEL:-unknown}"
  printf '  %-16s %s\n' "Arch"        "${SYSTEM_ARCH:-unknown}"
  printf '  %-16s %s\n' "RAM"         "${SYSTEM_RAM_MB:-0} MB"
  printf '  %-16s %s\n' "Firmware"    "${SYSTEM_FIRMWARE:-unknown}"
  printf '  %-16s %s\n' "Boot device" "${SYSTEM_BOOT_DEVICE:-unknown}"
  echo
  echo "Runtime"
  local throttled temp governor
  if command -v vcgencmd >/dev/null 2>&1; then
    throttled=$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2)
    temp=$(vcgencmd measure_temp 2>/dev/null | cut -d= -f2)
  else
    throttled="(vcgencmd not available)"
    temp="(vcgencmd not available)"
  fi
  if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)
  else
    governor="(cpufreq unavailable)"
  fi
  printf '  %-16s %s\n' "Throttle"     "$throttled"
  printf '  %-16s %s\n' "SoC temp"     "$temp"
  printf '  %-16s %s\n' "CPU governor" "$governor"
  if command -v swapon >/dev/null 2>&1; then
    printf '  %-16s %s\n' "Swap"       "$(swapon --show --noheadings 2>/dev/null | awk '{printf "%s %s %s ", $1, $3, $4}' | sed 's/ $//')"
  fi
  if command -v zramctl >/dev/null 2>&1; then
    printf '  %-16s %s\n' "ZRAM"       "$(zramctl --noheadings 2>/dev/null | awk '{printf "%s %s ratio=%s ", $1, $2, $5}' | sed 's/ $//')"
  fi
  echo
  echo "Disk (root)"
  df -Ph / 2>/dev/null | awk 'NR==2 {printf "  %-16s %s used of %s (%s)\n", "Root", $3, $2, $5}'
  if [[ -e /boot/firmware ]]; then
    df -Ph /boot/firmware 2>/dev/null | awk 'NR==2 {printf "  %-16s %s used of %s (%s)\n", "/boot/firmware", $3, $2, $5}'
  fi
  echo
  echo "Tasks"
  printf '  %-16s %s\n' "State schema" "v$(pi_state_schema_version)"
  local total=${#PI_TASK_ORDER[@]} done=0 failed=0 pending=0
  local tid
  for tid in "${PI_TASK_ORDER[@]}"; do
    if get_task_state "$tid"; then
      case $TASK_STATE_STATUS in
        completed) done=$((done+1)) ;;
        failed)    failed=$((failed+1)) ;;
        *)         pending=$((pending+1)) ;;
      esac
    else
      pending=$((pending+1))
    fi
  done
  printf '  %-16s %d registered / %d completed / %d failed / %d pending\n' \
    "Registry" "$total" "$done" "$failed" "$pending"
  echo
  echo "Optional integrations"
  local line
  for line in \
    "tailscale::tailscale" \
    "docker::docker" \
    "fail2ban::fail2ban-client" \
    "rpi-update::rpi-update" \
    "rpi-eeprom-update::rpi-eeprom-update" \
    ; do
    local label=${line%%::*}
    local bin=${line##*::}
    if command -v "$bin" >/dev/null 2>&1; then
      printf '  %-16s installed (%s)\n' "$label" "$(command -v "$bin")"
    else
      printf '  %-16s not installed\n' "$label"
    fi
  done
  echo "$divider"
}

_pi_generate_report_json() {
  STATE_JSON_PATH="$STATE_JSON_FILE" \
  PI_ORDER_LIST="${PI_TASK_ORDER[*]}" \
  PI_MODEL="${SYSTEM_MODEL:-}" \
  PI_GEN="${SYSTEM_PI_GEN:-}" \
  PI_KERNEL="${SYSTEM_KERNEL:-}" \
  PI_ARCH="${SYSTEM_ARCH:-}" \
  PI_RAM="${SYSTEM_RAM_MB:-0}" \
  PI_FIRMWARE="${SYSTEM_FIRMWARE:-}" \
  PI_BOOT_DEV="${SYSTEM_BOOT_DEVICE:-}" \
  run_python <<'PY'
import json, os, subprocess, sys

def safe_run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout.strip()
    except Exception:
        return ""

try:
    with open(os.environ["STATE_JSON_PATH"]) as fh:
        state = json.load(fh)
except Exception:
    state = {}

tasks_state = state.get("tasks") or {}
order = os.environ.get("PI_ORDER_LIST", "").split()
summary = {"completed": 0, "failed": 0, "pending": 0}
for tid in order:
    st = tasks_state.get(tid, {}).get("status", "pending")
    summary[st] = summary.get(st, 0) + 1

out = {
    "generated_at": safe_run(["date", "-Iseconds"]),
    "system": {
        "model": os.environ["PI_MODEL"],
        "pi_gen": os.environ["PI_GEN"],
        "kernel": os.environ["PI_KERNEL"],
        "arch": os.environ["PI_ARCH"],
        "ram_mb": int(os.environ["PI_RAM"] or 0),
        "firmware": os.environ["PI_FIRMWARE"],
        "boot_device": os.environ["PI_BOOT_DEV"],
    },
    "runtime": {
        "throttled": safe_run(["vcgencmd", "get_throttled"]).split("=", 1)[-1],
        "soc_temp": safe_run(["vcgencmd", "measure_temp"]).split("=", 1)[-1],
    },
    "schema_version": state.get("schema_version", 2),
    "task_summary": {
        "total": len(order),
        **summary,
    },
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
}
