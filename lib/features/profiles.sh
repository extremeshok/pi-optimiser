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
    { "name": "kiosk",        "enables": ["INSTALL_ZRAM", "WIFI_POWERSAVE_OFF", "SECURE_SSH"] },
    { "name": "server",       "enables": ["INSTALL_ZRAM", "SECURE_SSH", "INSTALL_SMARTMONTOOLS", "INSTALL_NODE_EXPORTER", "ENABLE_DNS_CACHE", "KEEP_SCREEN_BLANKING"] },
    { "name": "desktop",      "enables": ["INSTALL_CLI_MODERN"] },
    { "name": "headless-iot", "enables": ["INSTALL_WATCHDOG", "DISABLE_BLUETOOTH", "WIFI_POWERSAVE_OFF", "REQUEST_UNDERCLOCK", "KEEP_SCREEN_BLANKING"] }
  ]
}
JSON
    return 0
  fi
  cat <<'EOF'
Profiles:
  kiosk         HDMI kiosk — ZRAM, Wi-Fi never sleeps, SSH hardened.
  server        Headless server — ZRAM, hardened SSH, smartd,
                node_exporter, DNS cache. No HDMI (keeps blanking).
  desktop       GUI Pi — modern CLI bundle; leave swap alone.
  headless-iot  Zero 2 / Pi 3 class — watchdog, no Bluetooth,
                Wi-Fi never sleeps, underclock, no HDMI work.

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
  if [[ $rc -eq 0 ]]; then
    echo "Config OK: $path"
    return 0
  fi
  echo "Config validation failed for $path (rc=$rc)" >&2
  return 1
}

# shellcheck disable=SC2034  # globals set here are read by lib/tasks/*.sh
pi_apply_profile() {
  local name=${1,,}
  case $name in
    kiosk)
      # Always-on HDMI screens: keep display on, ZRAM, performance gov,
      # no SSH brute-force window, WiFi doesn't nap.
      INSTALL_ZRAM=1
      WIFI_POWERSAVE_OFF=1
      SECURE_SSH=1
      # screen_blanking runs by default — don't set KEEP_SCREEN_BLANKING.
      ;;
    server)
      # Headless server: tmpfs-heavy, ZRAM, SSH hardened + key import
      # expected, smartd for NVMe, node_exporter for metrics, no HDMI.
      INSTALL_ZRAM=1
      SECURE_SSH=1
      INSTALL_SMARTMONTOOLS=1
      INSTALL_NODE_EXPORTER=1
      ENABLE_DNS_CACHE=1
      KEEP_SCREEN_BLANKING=1  # no display, skip the screen_blanking work
      ;;
    desktop)
      # GUI Pi: keep swap, modern CLI bundle, no aggressive service cull.
      INSTALL_CLI_MODERN=1
      ;;
    headless-iot)
      # Zero 2 / Pi 3 class low-power: watchdog, no Bluetooth, underclock,
      # no HDMI, no power-save on WiFi (want reliable connectivity).
      INSTALL_WATCHDOG=1
      DISABLE_BLUETOOTH=1
      WIFI_POWERSAVE_OFF=1
      REQUEST_UNDERCLOCK=1
      KEEP_SCREEN_BLANKING=1
      ;;
    *)
      echo "pi-optimiser: unknown profile '$1' (expected kiosk|server|desktop|headless-iot)" >&2
      exit 1
      ;;
  esac
  log_info "Applied profile: $name (flags may still be overridden by later CLI args)"
}
