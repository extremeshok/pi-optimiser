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

# Write a log message with level tag to stdout and log file.
log_with_level() {
  local level=$1
  shift
  local timestamp message
  timestamp=$(date +'%Y-%m-%d %H:%M:%S')
  message="$timestamp [$level] $*"
  if [[ "$level" == "ERROR" ]]; then
    echo "$message" >&2
  else
    echo "$message"
  fi
  echo "$message" >> "$LOG_FILE"
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
