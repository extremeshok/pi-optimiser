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

# https:// URL validation for key-import URLs. Enforces:
#   - scheme must be exactly `https://`  (rejects http/file/javascript:)
#   - no whitespace, CR/LF, backticks, quotes, or shell metacharacters
#     that could smuggle into `curl "$URL"` argv or header-injection
#     downstream
#   - no `user[:pass]@host` credentials embedded in the URL (we don't
#     want curl to quietly log-leak a password on retry)
#   - overall length capped so a pathological value can't DoS logs
validate_https_url() {
  local url=$1
  [[ -n "$url" ]] || return 1
  (( ${#url} <= 2048 )) || return 1
  [[ $url == https://* ]] || return 1
  # Reject whitespace, control chars, backticks, backslashes, quotes,
  # semicolons, pipes, angle brackets, parentheses, and braces. These
  # aren't legal in an RFC 3986 URI and several are shell/CR/LF bait.
  [[ $url == *[[:space:][:cntrl:]\`\\\'\"\;\|\<\>\(\)\{\}]* ]] && return 1
  # Reject `user@host` / `user:pass@host` in the authority. Scan the
  # substring between `https://` and the next `/` (or end-of-string).
  local rest=${url#https://}
  local authority=${rest%%/*}
  [[ $authority == *@* ]] && return 1
  return 0
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

# GitHub repository path, as owner/name. Used before interpolating
# PI_OPTIMISER_REPO into GitHub API and codeload URLs.
validate_github_repo() {
  [[ $1 =~ ^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$ ]] \
    && [[ $1 != *".."* ]]
}

# Branch, tag, or commit-ish ref safe for URL path interpolation.
validate_git_ref() {
  [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,127}$ ]] \
    && [[ $1 != *".."* ]] \
    && [[ $1 != *"//"* ]] \
    && [[ $1 != *"@{"* ]] \
    && [[ $1 != *.lock ]]
}

validate_commit_sha() {
  [[ $1 =~ ^[0-9a-fA-F]{40}$ ]]
}

validate_metrics_path() {
  local path=$1
  [[ -n "$path" ]] || return 1
  [[ "$path" == /* ]] || return 1
  [[ "$path" == *.prom ]] || return 1
  [[ "$path" != *[[:cntrl:][:space:]\`\\\'\"\;\|\<\>\(\)\{\}]* ]] || return 1
  [[ "$path" != *"/../"* && "$path" != */.. && "$path" != *"/./"* ]] || return 1
  return 0
}

validate_usb_uas_list() {
  [[ $1 =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}(:[a-z]+)?(,[0-9a-fA-F]{4}:[0-9a-fA-F]{4}(:[a-z]+)?)*$ ]]
}

# Locale identifier: `ll_CC[.encoding][@modifier]` (POSIX locale format).
# Rejects whitespace, newlines, shell metacharacters, and path traversal
# so the value can be safely written into /etc/default/locale (which is
# shell-sourced by /etc/profile) and passed to update-locale.
validate_locale() {
  [[ $1 =~ ^[A-Za-z]{1,8}(_[A-Za-z]{1,8})?(\.[A-Za-z0-9-]{1,32})?(@[A-Za-z0-9]{1,32})?$ ]] \
    || [[ $1 == "C" || $1 == "C.UTF-8" || $1 == "POSIX" ]]
}

# IANA timezone name: `Region/City[/Sub]`. Strict regex rejects path
# traversal (`..`), absolute paths, and shell metacharacters so the
# value can be safely passed to timedatectl, symlinked under
# /etc/localtime, and written to /etc/timezone. The caller still
# verifies that /usr/share/zoneinfo/$tz exists.
validate_timezone_name() {
  [[ $1 =~ ^[A-Za-z][A-Za-z0-9_+-]{0,63}(/[A-Za-z][A-Za-z0-9_+-]{0,63}){0,3}$ ]] \
    || [[ $1 == "UTC" ]]
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
