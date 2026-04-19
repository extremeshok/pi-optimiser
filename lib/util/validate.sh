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

# Validate a proxy-backend URL (used by task_configure_proxy) is a
# well-formed http(s) URL with no characters that could break out of
# the `proxy_pass $PROXY_BACKEND;` nginx directive. Rejects semicolons,
# braces, whitespace, newlines, and backticks to prevent directive
# injection even when the YAML loader has quoted the value correctly.
validate_proxy_backend_url() {
  local url=$1
  [[ -n "$url" ]] || return 1
  # Allow only http:// or https:// followed by a character set safe for
  # nginx's proxy_pass directive (hostname, port, path, query, user@).
  if [[ $url =~ ^https?://[A-Za-z0-9._:/@%\?\&=\-]+$ ]]; then
    return 0
  fi
  return 1
}

# GitHub login handle validator: 1..39 characters, alphanumerics and
# single hyphens, no leading/trailing hyphen. Matches GitHub's real
# rules closely enough to reject shell-dangerous inputs.
validate_github_handle() {
  [[ $1 =~ ^[A-Za-z0-9](-?[A-Za-z0-9]){0,38}$ ]]
}

# Task IDs are snake_case; reject path-traversal and other surprises
# before we use the id to build a journal path.
validate_task_id() {
  [[ $1 =~ ^[a-z][a-z0-9_]{0,63}$ ]]
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
