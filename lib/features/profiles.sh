# ======================================================================
# lib/features/profiles.sh — curated flag bundles
#
# Functions: pi_apply_profile
#
# Called from parse_args when --profile <name> is seen. Profiles set
# the flag globals BEFORE subsequent CLI args are parsed, so any
# explicit flag following --profile wins (left-to-right precedence).
# ======================================================================

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
