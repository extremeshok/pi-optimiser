# ======================================================================
# lib/util/log.sh — logging primitives
#
# Functions: init_logging, log_info, log_warn, log_error, log_with_level,
#            on_err
# Globals (read):  LOG_FILE, CURRENT_TASK
# Globals (write): none
# ======================================================================

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

# Write a log message with level tag to stdout and log file. The
# log-file append is best-effort — non-root invocations (--version,
# --help, etc.) can't write to /var/log/pi-optimiser.log but must not
# leak a "Permission denied" error to the user.
#
# When PI_OUTPUT_JSON=1, all log lines go to stderr so stdout is a
# clean JSON stream for `--status --output json`, `--report --output
# json`, `--check-update --output json`, etc.
log_with_level() {
  local level=$1
  shift
  local timestamp message
  timestamp=$(date +'%Y-%m-%d %H:%M:%S')
  message="$timestamp [$level] $*"
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
