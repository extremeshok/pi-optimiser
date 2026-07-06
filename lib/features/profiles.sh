# ======================================================================
# lib/features/profiles.sh — curated flag bundles
#
# Functions: pi_apply_profile
#
# Called from parse_args when --profile <name> is seen. Profiles set
# the flag globals BEFORE subsequent CLI args are parsed, so any
# explicit flag following --profile wins (left-to-right precedence).
# ======================================================================

# Print every profile alongside what it toggles so users can decide
# which one to pick. Honours --output json for scriptable consumers.
pi_list_profiles() {
  if [[ ${PI_OUTPUT_JSON:-0} -eq 1 ]]; then
    cat <<'JSON'
{
  "profiles": [
    { "name": "kiosk",        "enables": ["INSTALL_ZRAM", "WIFI_POWERSAVE_OFF", "SECURE_SSH", "QUIET_BOOT", "INSTALL_KIOSK_MONITOR"] },
    { "name": "server",       "enables": ["INSTALL_ZRAM", "SECURE_SSH", "INSTALL_SMARTMONTOOLS", "INSTALL_NODE_EXPORTER", "ENABLE_DNS_CACHE", "INSTALL_FIREWALL", "INSTALL_OMNIBAN", "DISABLE_LEDS", "HEADLESS_GPU_MEM", "KEEP_SCREEN_BLANKING"] },
    { "name": "desktop",      "enables": ["INSTALL_CLI_MODERN"] },
    { "name": "headless-iot", "enables": ["INSTALL_WATCHDOG", "DISABLE_BLUETOOTH", "WIFI_POWERSAVE_OFF", "REQUEST_UNDERCLOCK", "DISABLE_LEDS", "QUIET_BOOT", "HEADLESS_GPU_MEM", "KEEP_SCREEN_BLANKING"] }
  ]
}
JSON
    return 0
  fi
  cat <<'EOF'
Profiles:
  kiosk         HDMI kiosk — ZRAM, Wi-Fi never sleeps, SSH hardened,
                quiet boot (no rainbow splash), kiosk-monitor watchdog.
  server        Headless server — ZRAM, hardened SSH, smartd,
                node_exporter, DNS cache, UFW firewall, omniban ban
                manager, LEDs off.
  desktop       GUI Pi — modern CLI bundle; leave swap alone.
  headless-iot  Zero 2 / Pi 3 class — watchdog, no Bluetooth,
                Wi-Fi never sleeps, underclock, LEDs off, quiet boot.

Profiles set flag globals before the rest of parse_args runs, so
anything specified later on the CLI overrides the profile default.
EOF
}

# Validate a config.yaml by loading it into a subshell and checking
# that the loader returns non-zero or emits no warnings. Separate from
# pi_config_load so we can short-circuit without touching the live
# globals in the running process.
pi_validate_config() {
  local path=$1
  if [[ ! -f "$path" ]]; then
    echo "pi-optimiser: config file not found: $path" >&2
    return 1
  fi
  # Run the loader in a subshell so we don't pollute globals.
  local rc=0
  ( pi_config_load "$path" ) >/dev/null 2>&1 || rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "Config validation failed for $path (rc=$rc)" >&2
    return 1
  fi
  # Even when the YAML parses, enforce that at least one recognised
  # top-level key is present. Otherwise /etc/hosts or a blank file
  # would pass.
  CFG_PATH="$path" run_python <<'PY' || { echo "Config has no recognised pi-optimiser keys: $path" >&2; return 1; }
import os, sys
path = os.environ["CFG_PATH"]
known_top = {"version", "profile", "integrations", "hardware",
             "firmware", "security", "system", "refresh",
             "metrics", "freeze_tasks"}
seen = set()
with open(path) as fh:
    for raw in fh:
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent != 0:
            continue
        key, _, _v = line.strip().partition(":")
        seen.add(key.strip())
common = seen & known_top
if not common:
    sys.exit(1)
PY
  echo "Config OK: $path"
  return 0
}

# Run every task's preconditions read-only so the operator can see
# which tasks would apply without any side effects. Emits a compact
# per-task pass/fail/skip table.
pi_self_test() {
  local bin
  local -a missing_bins=()
  local -a required=(python3 awk sed grep find tar curl bash systemctl)
  for bin in "${required[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || missing_bins+=("$bin")
  done
  echo "pi-optimiser self-test"
  echo "  script version  $SCRIPT_VERSION"
  echo "  model           ${SYSTEM_MODEL:-unknown}"
  echo "  pi_gen          ${SYSTEM_PI_GEN:-unknown}"
  echo "  arch            ${SYSTEM_ARCH:-unknown}"
  echo "  RAM             ${SYSTEM_RAM_MB:-0} MB"
  echo "  root device     ${SYSTEM_BOOT_DEVICE:-unknown}"
  echo "  config.txt      ${CONFIG_TXT_FILE:-/boot/firmware/config.txt}"
  echo "  cmdline.txt     ${CMDLINE_FILE:-/boot/firmware/cmdline.txt}"
  echo "  lock file       /var/lock/pi-optimiser.lock"
  echo "  schema version  v$(pi_state_schema_version)"
  if (( ${#missing_bins[@]} > 0 )); then
    echo "  MISSING BINS    ${missing_bins[*]}"
  else
    echo "  required bins   all present"
  fi
  echo
  echo "Task preconditions:"
  local any_fail=0 tid cat ok
  printf '  %-22s %-18s %s\n' "TASK" "CATEGORY" "PRECONDITIONS"
  for tid in "${PI_TASK_ORDER[@]}"; do
    cat=${PI_TASK_CATEGORY[$tid]:-unknown}
    ok="ok"
    # Power-sensitive tasks that would be blocked
    if [[ ${PI_TASK_POWER_SENSITIVE[$tid]:-0} == "1" && ${POWER_HEALTHY:-1} -eq 0 ]]; then
      ok="SKIP (power/thermal blocker)"
      any_fail=1
    fi
    # Pi5-only tasks on non-Pi5
    case "$tid" in
      pi5_fan|pcie_gen3)
        is_pi5 || { ok="SKIP (not Pi5)"; any_fail=1; }
        ;;
    esac
    # EEPROM tasks on non-Pi4/5
    case "$tid" in
      eeprom_config|eeprom_refresh)
        pi_supports_eeprom \
          || { ok="SKIP (no EEPROM support)"; any_fail=1; }
        ;;
    esac
    printf '  %-22s %-18s %s\n' "$tid" "$cat" "$ok"
  done
  echo
  if (( any_fail == 0 )); then
    echo "All task preconditions satisfied."
    return 0
  fi
  echo "Some tasks would be skipped on this hardware (see above)."
  return 0
}

# Dump the effective config — what would actually take effect if
# `pi-optimiser --yes --no-tui` ran right now (after merging CLI
# flags over config.yaml over defaults). Honours --output json.
pi_show_effective_config() {
  # Bash forbids `${!arr[*]:-default}` (the `:-` conflicts with the
  # indirect-expansion `!` prefix), so materialise the frozen-task list
  # into a plain scalar first and interpolate that.
  local _frozen_ids=""
  if (( ${#PI_FROZEN_TASKS[@]} > 0 )); then
    _frozen_ids="${!PI_FROZEN_TASKS[*]}"
  fi
  local _refresh_pairs="" _refresh_task _refresh_value
  if declare -p PI_TASK_REFRESH_DAYS >/dev/null 2>&1; then
    for _refresh_task in "${!PI_TASK_REFRESH_DAYS[@]}"; do
      [[ -n "${PI_TASK_REFRESH_DAYS[$_refresh_task]:-}" ]] || continue
      _refresh_value=${PI_REFRESH_TASK_MIN_DAYS[$_refresh_task]:-${PI_TASK_REFRESH_DAYS[$_refresh_task]}}
      _refresh_pairs+="${_refresh_task}=${_refresh_value}"$'\n'
    done
  fi
  local _refresh_lines=""
  if [[ -n "$_refresh_pairs" ]]; then
    local _rt _rv
    while IFS='=' read -r _rt _rv; do
      [[ -n "$_rt" ]] || continue
      _refresh_lines+="$(printf '  %-20s %s' "$_rt" "$_rv")"$'\n'
    done <<< "$_refresh_pairs"
  else
    _refresh_lines="$(printf '  %-20s %s\n' "tasks" "<none>")"
  fi
  local _usb_gadget_mode="" _sudo_policy_mode=""
  if [[ ${USB_GADGET_DISABLE:-0} -eq 1 ]]; then
    _usb_gadget_mode="disable"
  elif [[ ${USB_GADGET_SET:-0} -eq 1 || ${USB_GADGET_ENABLE:-0} -eq 1 ]]; then
    _usb_gadget_mode="enable"
  fi
  if [[ ${SUDO_POLICY_PASSWORDLESS:-0} -eq 1 ]]; then
    _sudo_policy_mode="passwordless"
  elif [[ ${SUDO_POLICY_SET:-0} -eq 1 || ${SUDO_POLICY_REQUIRED:-0} -eq 1 ]]; then
    _sudo_policy_mode="password-required"
  fi
  if [[ ${PI_OUTPUT_JSON:-0} -eq 1 ]]; then
    V_TAILSCALE="${INSTALL_TAILSCALE:-0}" \
    V_DOCKER="${INSTALL_DOCKER:-0}" \
    V_DOCKER_BUILDX="${DOCKER_BUILDX_MULTIARCH:-0}" \
    V_DOCKER_CGV2="${DOCKER_CGROUPV2:-0}" \
    V_WIREGUARD="${INSTALL_WIREGUARD:-0}" \
    V_ALLOW_BOTH_VPN="${ALLOW_BOTH_VPN:-0}" \
    V_ZRAM="${INSTALL_ZRAM:-0}" \
    V_ZRAM_ALGO="${ZRAM_ALGO_OVERRIDE:-}" \
    V_NODE_EXPORTER="${INSTALL_NODE_EXPORTER:-0}" \
    V_SMARTMON="${INSTALL_SMARTMONTOOLS:-0}" \
    V_CLI_MODERN="${INSTALL_CLI_MODERN:-0}" \
    V_NET_DIAG="${INSTALL_NET_DIAG:-0}" \
    V_DNS_CACHE="${ENABLE_DNS_CACHE:-0}" \
    V_PI_CONNECT="${INSTALL_PI_CONNECT:-0}" \
    V_HAILO="${INSTALL_HAILO:-0}" \
    V_HAILO_HW="${HAILO_HARDWARE:-auto}" \
    V_CHRONY="${INSTALL_CHRONY:-0}" \
    V_DISABLE_IPV6="${DISABLE_IPV6:-0}" \
    V_OMNIBAN="${INSTALL_OMNIBAN:-0}" \
    V_KIOSK_MONITOR="${INSTALL_KIOSK_MONITOR:-0}" \
    V_OC="${REQUEST_OC_CONSERVATIVE:-0}" \
    V_UNDERCLOCK="${REQUEST_UNDERCLOCK:-0}" \
    V_WATCHDOG="${INSTALL_WATCHDOG:-0}" \
    V_PI5FAN="${INSTALL_PI5_FAN_PROFILE:-0}" \
    V_PCIE3="${INSTALL_PCIE_GEN3:-0}" \
    V_WIFI="${WIFI_POWERSAVE_OFF:-0}" \
    V_DISBT="${DISABLE_BLUETOOTH:-0}" \
    V_QUIET_BOOT="${QUIET_BOOT:-0}" \
    V_DISABLE_LEDS="${DISABLE_LEDS:-0}" \
    V_NVME_TUNE="${NVME_TUNE:-0}" \
    V_HEADLESS_GPU="${HEADLESS_GPU_MEM:-0}" \
    V_USB_UAS="${USB_UAS_QUIRKS:-0}" \
    V_USB_UAS_EXTRA="${USB_UAS_EXTRA:-}" \
    V_USB_GADGET_MODE="$_usb_gadget_mode" \
    V_FW_UPDATE="${FIRMWARE_UPDATE:-0}" \
    V_EEPROM="${EEPROM_UPDATE:-0}" \
    V_POWER_OFF_HALT="${POWER_OFF_HALT:-0}" \
    V_SECURE_SSH="${SECURE_SSH:-0}" \
    V_FIREWALL="${INSTALL_FIREWALL:-0}" \
    V_SUDO_POLICY="$_sudo_policy_mode" \
    V_HOSTNAME="${REQUESTED_HOSTNAME:-}" \
    V_TZ="${REQUESTED_TIMEZONE:-}" \
    V_LOCALE="${REQUESTED_LOCALE:-}" \
    V_KEEP_BLANK="${KEEP_SCREEN_BLANKING:-0}" \
    V_REMOVE_CUPS="${REMOVE_CUPS:-0}" \
    V_CLOUD_INIT_FINALIZE="${CLOUD_INIT_FINALIZE:-0}" \
    V_PROXY="${PROXY_BACKEND:-}" \
    V_PROFILE="${PI_PROFILE:-}" \
    V_DRYRUN="${DRY_RUN:-0}" \
    V_FORCE="${FORCE:-0}" \
    V_GH="${SSH_IMPORT_GITHUB:-}" \
    V_URL="${SSH_IMPORT_URL:-}" \
    V_METRICS_ENABLED="${PI_METRICS_ENABLED:-1}" \
    V_METRICS_PATH="${PI_METRICS_PATH:-}" \
    V_REFRESH_DEFAULT="${PI_REFRESH_DEFAULT_MIN_DAYS:-}" \
    V_REFRESH_TASKS="$_refresh_pairs" \
    V_WATCH="${PI_WATCH:-0}" \
    V_DIFF="${PI_DIFF_MODE:-0}" \
    V_FROZEN="$_frozen_ids" \
    run_python <<'PY'
import json, os, sys
def b(name): return os.environ.get(name, "0") == "1"
def s(name): return os.environ.get(name, "") or None
def refresh_tasks():
    out = {}
    for raw in os.environ.get("V_REFRESH_TASKS", "").splitlines():
        if "=" not in raw:
            continue
        task, value = raw.split("=", 1)
        if task and value:
            out[task] = value
    return out or None
out = {
    "runtime": {
        "dry_run": b("V_DRYRUN"),
        "force": b("V_FORCE"),
        "profile": s("V_PROFILE"),
    },
    "integrations": {
        "tailscale": b("V_TAILSCALE"),
        "wireguard": b("V_WIREGUARD"),
        "allow_both_vpn": b("V_ALLOW_BOTH_VPN"),
        "docker": {
            "enabled": b("V_DOCKER"),
            "buildx_multiarch": b("V_DOCKER_BUILDX"),
            "cgroup_v2": b("V_DOCKER_CGV2"),
        },
        "zram": {"enabled": b("V_ZRAM"), "algo": s("V_ZRAM_ALGO") or "lz4"},
        "proxy_backend": s("V_PROXY"),
        "node_exporter": b("V_NODE_EXPORTER"),
        "smartmontools": b("V_SMARTMON"),
        "cli_modern": b("V_CLI_MODERN"),
        "net_diag": b("V_NET_DIAG"),
        "dns_cache": b("V_DNS_CACHE"),
        "pi_connect": b("V_PI_CONNECT"),
        "hailo": b("V_HAILO"),
        "hailo_hardware": s("V_HAILO_HW") or "auto",
        "chrony": b("V_CHRONY"),
        "disable_ipv6": b("V_DISABLE_IPV6"),
        "omniban": b("V_OMNIBAN"),
        "kiosk_monitor": b("V_KIOSK_MONITOR"),
    },
    "hardware": {
        "overclock_conservative": b("V_OC"),
        "underclock": b("V_UNDERCLOCK"),
        "pi5_fan_profile": b("V_PI5FAN"),
        "pcie_gen3": b("V_PCIE3"),
        "watchdog": b("V_WATCHDOG"),
        "wifi_powersave_off": b("V_WIFI"),
        "disable_bluetooth": b("V_DISBT"),
        "quiet_boot": b("V_QUIET_BOOT"),
        "disable_leds": b("V_DISABLE_LEDS"),
        "nvme_tune": b("V_NVME_TUNE"),
        "headless_gpu_mem": b("V_HEADLESS_GPU"),
        "usb_uas_quirks": b("V_USB_UAS"),
        "usb_uas_extra": s("V_USB_UAS_EXTRA"),
        "usb_gadget": s("V_USB_GADGET_MODE"),
    },
    "firmware": {
        "firmware_update": b("V_FW_UPDATE"),
        "eeprom_update": b("V_EEPROM"),
        "power_off_halt": b("V_POWER_OFF_HALT"),
    },
    "security": {
        "secure_ssh": b("V_SECURE_SSH"),
        "firewall": b("V_FIREWALL"),
        "sudo_policy": s("V_SUDO_POLICY"),
        "ssh_import_github": s("V_GH"),
        "ssh_import_url": s("V_URL"),
    },
    "system": {
        "hostname": s("V_HOSTNAME"),
        "timezone": s("V_TZ"),
        "locale": s("V_LOCALE"),
        "keep_screen_blanking": b("V_KEEP_BLANK"),
        "remove_cups": b("V_REMOVE_CUPS"),
        "cloud_init_finalize": b("V_CLOUD_INIT_FINALIZE"),
    },
    "refresh": {
        "default_min_days": s("V_REFRESH_DEFAULT"),
        "tasks": refresh_tasks(),
    },
    "metrics": {
        "enabled": b("V_METRICS_ENABLED"),
        "path": s("V_METRICS_PATH"),
    },
    "watch": b("V_WATCH"),
    "diff_preview": b("V_DIFF"),
    "freeze_tasks": sorted((os.environ.get("V_FROZEN", "") or "").split()) or None,
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
    return 0
  fi
  cat <<CFG
Effective pi-optimiser config
(CLI flags override /etc/pi-optimiser/config.yaml which overrides defaults)

Runtime
  DRY_RUN             ${DRY_RUN:-0}
  FORCE               ${FORCE:-0}
  PI_NON_INTERACTIVE  ${PI_NON_INTERACTIVE:-0}
  PI_OUTPUT_JSON      ${PI_OUTPUT_JSON:-0}
  PI_PROFILE          ${PI_PROFILE:-<none>}

Integrations
  tailscale           ${INSTALL_TAILSCALE:-0}
  wireguard           ${INSTALL_WIREGUARD:-0}
  allow_both_vpn      ${ALLOW_BOTH_VPN:-0}
  docker              ${INSTALL_DOCKER:-0}
    buildx-multiarch  ${DOCKER_BUILDX_MULTIARCH:-0}
    cgroup-v2         ${DOCKER_CGROUPV2:-0}
  zram                ${INSTALL_ZRAM:-0}  (algo=${ZRAM_ALGO_OVERRIDE:-lz4})
  proxy-backend       ${PROXY_BACKEND:-<unset>}
  node_exporter       ${INSTALL_NODE_EXPORTER:-0}
  smartmontools       ${INSTALL_SMARTMONTOOLS:-0}
  cli_bundle_modern   ${INSTALL_CLI_MODERN:-0}
  net_diag_bundle     ${INSTALL_NET_DIAG:-0}
  dns_cache           ${ENABLE_DNS_CACHE:-0}
  pi_connect          ${INSTALL_PI_CONNECT:-0}
  hailo               ${INSTALL_HAILO:-0}  (hardware=${HAILO_HARDWARE:-auto})
  chrony              ${INSTALL_CHRONY:-0}
  disable_ipv6        ${DISABLE_IPV6:-0}
  omniban             ${INSTALL_OMNIBAN:-0}
  kiosk_monitor       ${INSTALL_KIOSK_MONITOR:-0}

Hardware / clocks
  overclock           ${REQUEST_OC_CONSERVATIVE:-0}
  underclock          ${REQUEST_UNDERCLOCK:-0}
  pi5_fan_profile     ${INSTALL_PI5_FAN_PROFILE:-0}
  pcie_gen3           ${INSTALL_PCIE_GEN3:-0}
  watchdog            ${INSTALL_WATCHDOG:-0}
  temp_limit          ${TEMP_LIMIT:-<unset>}
  temp_soft_limit     ${TEMP_SOFT_LIMIT:-<unset>}
  initial_turbo       ${INITIAL_TURBO:-<unset>}
  wifi_powersave_off  ${WIFI_POWERSAVE_OFF:-0}
  disable_bluetooth   ${DISABLE_BLUETOOTH:-0}
  quiet_boot          ${QUIET_BOOT:-0}
  disable_leds        ${DISABLE_LEDS:-0}
  nvme_tune           ${NVME_TUNE:-0}
  headless_gpu_mem    ${HEADLESS_GPU_MEM:-0}
  usb_uas_quirks      ${USB_UAS_QUIRKS:-0}
  usb_uas_extra       ${USB_UAS_EXTRA:-<unset>}
  usb_gadget          ${_usb_gadget_mode:-<unset>}

Firmware
  firmware-update     ${FIRMWARE_UPDATE:-0}
  eeprom-update       ${EEPROM_UPDATE:-0}
  power-off-halt      ${POWER_OFF_HALT:-0}

Security
  secure_ssh          ${SECURE_SSH:-0}
  firewall            ${INSTALL_FIREWALL:-0}
  sudo_policy         ${_sudo_policy_mode:-<unset>}
  ssh_import_github   ${SSH_IMPORT_GITHUB:-<unset>}
  ssh_import_url      ${SSH_IMPORT_URL:-<unset>}

System
  hostname            ${REQUESTED_HOSTNAME:-<unset>}
  timezone            ${REQUESTED_TIMEZONE:-<unset>}
  locale              ${REQUESTED_LOCALE:-<unset>}
  keep_screen_blanking ${KEEP_SCREEN_BLANKING:-0}
  remove_cups         ${REMOVE_CUPS:-0}
  cloud_init_finalize ${CLOUD_INIT_FINALIZE:-0}

Refresh
  default_min_days    ${PI_REFRESH_DEFAULT_MIN_DAYS:-<task defaults>}
${_refresh_lines}

Framework
  metrics_enabled     ${PI_METRICS_ENABLED:-1}
  metrics_path        ${PI_METRICS_PATH:-<default>}
  watch               ${PI_WATCH:-0}
  diff_preview        ${PI_DIFF_MODE:-0}
  freeze_tasks        ${_frozen_ids:-<none>}
CFG
}

# shellcheck disable=SC2034  # globals set here are read by lib/tasks/*.sh
pi_apply_profile() {
  local name=${1,,}
  case $name in
    kiosk)
      # Always-on HDMI screens: keep display on, ZRAM, performance gov,
      # no SSH brute-force window, WiFi doesn't nap. Quiet boot hides
      # the rainbow splash which looks unpolished on digital signage.
      INSTALL_ZRAM=1
      WIFI_POWERSAVE_OFF=1
      SECURE_SSH=1
      QUIET_BOOT=1
      INSTALL_KIOSK_MONITOR=1
      # screen_blanking runs by default — don't set KEEP_SCREEN_BLANKING.
      ;;
    server)
      # Headless server: tmpfs-heavy, ZRAM, SSH hardened + key import
      # expected, smartd for NVMe, node_exporter for metrics, no HDMI,
      # UFW firewall active, status LEDs off for rack hygiene. Shrink
      # the gpu_mem split on Pi 4 and older (no-op on Pi 5 which uses
      # unified memory — the task itself handles the model check).
      INSTALL_ZRAM=1
      SECURE_SSH=1
      INSTALL_SMARTMONTOOLS=1
      INSTALL_NODE_EXPORTER=1
      ENABLE_DNS_CACHE=1
      INSTALL_FIREWALL=1
      INSTALL_OMNIBAN=1
      DISABLE_LEDS=1
      HEADLESS_GPU_MEM=1
      KEEP_SCREEN_BLANKING=1  # no display, skip the screen_blanking work
      ;;
    desktop)
      # GUI Pi: keep swap, modern CLI bundle, no aggressive service cull.
      INSTALL_CLI_MODERN=1
      ;;
    headless-iot)
      # Zero 2 / Pi 3 class low-power: watchdog, no Bluetooth, underclock,
      # no HDMI, no power-save on WiFi (want reliable connectivity),
      # status LEDs off, quiet boot so serial console isn't spammed,
      # 16 MB GPU split (Zero 2's 512 MB RAM really wants that back).
      INSTALL_WATCHDOG=1
      DISABLE_BLUETOOTH=1
      WIFI_POWERSAVE_OFF=1
      REQUEST_UNDERCLOCK=1
      DISABLE_LEDS=1
      QUIET_BOOT=1
      HEADLESS_GPU_MEM=1
      KEEP_SCREEN_BLANKING=1
      ;;
    *)
      echo "pi-optimiser: unknown profile '$1' (expected kiosk|server|desktop|headless-iot)" >&2
      exit 1
      ;;
  esac
  log_info "Applied profile: $name (flags may still be overridden by later CLI args)"
}
