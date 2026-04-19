# ======================================================================
# lib/util/validate.sh — small validators and sanity checks
#
# Functions: require_root, validate_hostname, validate_timezone,
#            validate_https_url, arch_sanity_banner
# Globals (read): SYSTEM_ARCH, SYSTEM_PI_GEN
# ======================================================================

# Abort execution unless running as root.
require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
  fi
}

# RFC 1123 label: a-z/0-9/'-', 1..63 chars, no leading/trailing dash.
validate_hostname() {
  [[ $1 =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]
}

# Accept any zone that ships under /usr/share/zoneinfo.
validate_timezone() {
  [[ -f "/usr/share/zoneinfo/$1" ]]
}

# Basic https:// prefix validation for key-import URLs.
validate_https_url() {
  [[ $1 == https://* ]]
}

# Log a banner at startup if the kernel/arch is non-standard for a Pi.
# Warns (not blocks) on 32-bit/armv7 kernels, which Raspberry Pi OS has
# largely deprecated; most optimisations still work but overclock /
# EEPROM paths assume 64-bit firmware.
arch_sanity_banner() {
  local arch=${SYSTEM_ARCH:-$(uname -m)}
  case "$arch" in
    aarch64|arm64)
      # Expected — silent.
      ;;
    armv7l|armv6l|armv5*)
      log_warn "Running on $arch kernel — Raspberry Pi OS 64-bit (aarch64) is recommended. OC/EEPROM tasks may be skipped."
      ;;
    x86_64|amd64|i686)
      log_warn "Running on $arch — not a Raspberry Pi. Only generic Linux tasks will apply."
      ;;
    *)
      log_warn "Unrecognised architecture '$arch'. Proceeding, but some hardware tasks may no-op."
      ;;
  esac
}
