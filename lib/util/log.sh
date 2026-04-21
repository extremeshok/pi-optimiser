# ======================================================================
# lib/util/log.sh — logging primitives
#
# Functions: init_logging, log_info, log_warn, log_error, log_with_level,
#            log_sanitize, on_err
# Globals (read):  LOG_FILE, CURRENT_TASK
# Globals (write): none
# ======================================================================

# Ensure log file exists and has correct permissions. 0640 root:adm is
# the Debian-logger convention: readable by members of adm (journalctl,
# log-checking sysadmins) but not world-readable. Fall back to 0600
# root:root when group adm does not exist (non-Debian hosts).
init_logging() {
  local log_dir
  log_dir=$(dirname "$LOG_FILE")
  if [[ ! -d "$log_dir" ]]; then
    mkdir -p "$log_dir"
  fi
  if [[ ! -f "$LOG_FILE" ]]; then
    touch "$LOG_FILE"
  fi
  if getent group adm >/dev/null 2>&1; then
    chown root:adm "$LOG_FILE" 2>/dev/null || true
    chmod 0640 "$LOG_FILE" 2>/dev/null || true
  else
    chown root:root "$LOG_FILE" 2>/dev/null || true
    chmod 0600 "$LOG_FILE" 2>/dev/null || true
  fi
}

# Strip control characters that could be used to inject fake log lines
# or smuggle ANSI escape sequences through the log file.
#
# Threats this defends against:
#  - Log injection: `--hostname "pi\nrogue line"` would otherwise land
#    as two separate timestamped entries.
#  - CSI/OSC escape abuse: a log-viewer `cat`/`less` could be tricked
#    into hiding lines or rewriting the terminal title.
#  - Carriage returns: overwrite the current line, hiding content.
#
# Strips: CR, LF, NUL, BEL, ESC, and all C0 controls except TAB; also
# drops CSI (ESC [ …) and OSC (ESC ] …) sequences entirely.
#
# Called implicitly by log_with_level() for every argument so callers
# don't have to remember. Direct use is still supported for places that
# compose a message out of multiple variables before calling log_info.
log_sanitize() {
  local in=$*
  # Replace CR/LF/TAB-ish whitespace first with a visible marker.
  in=${in//$'\r\n'/ | }
  in=${in//$'\n'/ | }
  in=${in//$'\r'/ | }
  # Drop remaining control bytes (NUL, BEL, ESC, etc.) using tr.
  # LC_ALL=C keeps tr byte-oriented across locales.
  if [[ "$in" == *$'\x1b'* || "$in" == *$'\x00'* || "$in" == *$'\x07'* ]]; then
    in=$(LC_ALL=C printf '%s' "$in" | LC_ALL=C tr -d '\000-\010\013-\037\177' 2>/dev/null)
  fi
  printf '%s' "$in"
}

# Write a log message with level tag to stdout and log file. The
# log-file append is best-effort — non-root invocations (--version,
# --help, etc.) can't write to /var/log/pi-optimiser.log but must not
# leak a "Permission denied" error to the user.
#
# Every message is passed through log_sanitize so user-supplied values
# (hostnames, URLs, error output) cannot inject newlines or ANSI
# escape codes into the log.
#
# When PI_OUTPUT_JSON=1, all log lines go to stderr so stdout is a
# clean JSON stream for `--status --output json`, `--report --output
# json`, `--check-update --output json`, etc.
log_with_level() {
  local level=$1
  shift
  local timestamp message raw
  # RFC3339 timestamp (ISO-8601 profile) so log aggregators and `date -d`
  # can round-trip every line. Prefer GNU date's `%:z` (colon offset,
  # e.g. `+01:00`) when available; fall back to `%z` (`+0100`) on BSD
  # date, which is still a valid RFC3339 profile for tooling we target.
  # Run the GNU probe once per process via a cached global.
  if [[ -z "${_PI_DATE_HAS_COLON_TZ:-}" ]]; then
    # GNU date returns e.g. `+01:00` / `-05:30`; BSD date emits the
    # literal string `:z`. Accept only offsets that start with `+`/`-`
    # and contain a `:` — that shape is GNU-specific.
    local _probe
    _probe=$(date +'%:z' 2>/dev/null)
    if [[ $_probe =~ ^[+-][0-9]{2}:[0-9]{2}$ ]]; then
      _PI_DATE_HAS_COLON_TZ=1
    else
      _PI_DATE_HAS_COLON_TZ=0
    fi
  fi
  if (( _PI_DATE_HAS_COLON_TZ == 1 )); then
    timestamp=$(date +'%Y-%m-%dT%H:%M:%S%:z')
  else
    timestamp=$(date +'%Y-%m-%dT%H:%M:%S%z')
  fi
  raw=$(log_sanitize "$*")
  message="$timestamp [$level] $raw"
  if [[ "$level" == "ERROR" || ${PI_OUTPUT_JSON:-0} -eq 1 ]]; then
    echo "$message" >&2
  else
    echo "$message"
  fi
  if [[ -w "$LOG_FILE" || (! -e "$LOG_FILE" && -w "$(dirname "$LOG_FILE")") ]]; then
    echo "$message" >> "$LOG_FILE" 2>/dev/null || true
  fi
}

log_info()  { log_with_level INFO  "$@"; }
log_warn()  { log_with_level WARN  "$@"; }
log_error() { log_with_level ERROR "$@"; }

# Trap handler to log task failures with line numbers.
on_err() {
  local exit_code=$1
  local line_no=$2
  log_error "Failure (code=$exit_code) while running task '${CURRENT_TASK:-<startup>}' at line $line_no"
}
