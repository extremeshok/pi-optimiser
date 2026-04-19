# ======================================================================
# lib/features/watch.sh — re-run pi-optimiser when config.yaml changes
#
# --watch runs the main pipeline once, drops the flock, then blocks on
# inotifywait(1) against the config.yaml path. Each detected change
# re-execs $0 with the original argv minus --watch (so the child pass
# runs once and exits, rather than recursing into another watch loop).
#
# Requires inotify-tools; falls back to a 10-second polling loop if
# it's missing. A 2-second debounce groups editor save-temp / rename
# bursts so saving from vim / nano doesn't trigger multiple re-runs.
#
# Functions: pi_watch_loop
# Globals (read): PI_WATCH, PI_CONFIG_FILE, PI_CONFIG_DEFAULT,
#                 PI_WATCH_ARGV
# ======================================================================

_pi_watch_target() {
  printf '%s\n' "${PI_CONFIG_FILE:-${PI_CONFIG_DEFAULT:-/etc/pi-optimiser/config.yaml}}"
}

# Block until the config file changes. Returns 0 on change, 1 if we
# cannot watch at all (so the caller can exit instead of spinning).
_pi_watch_wait() {
  local target=$1
  # If the file hasn't been created yet, watch its parent directory
  # instead — inotifywait errors when pointed at a non-existent file.
  if [[ ! -f "$target" ]]; then
    local parent
    parent=$(dirname "$target")
    mkdir -p "$parent" 2>/dev/null || true
    if command -v inotifywait >/dev/null 2>&1; then
      while [[ ! -f "$target" ]]; do
        inotifywait -qq --event create,moved_to "$parent" 2>/dev/null || return 1
      done
    else
      while [[ ! -f "$target" ]]; do sleep 5; done
    fi
    return 0
  fi
  if command -v inotifywait >/dev/null 2>&1; then
    # close_write,move,delete,create catches both in-place writes and
    # editor rename-on-save flows. If inotifywait fails (e.g. the file
    # was replaced atomically), sleep briefly so the caller can retry.
    if inotifywait -qq --event close_write,move,delete,create "$target" 2>/dev/null; then
      return 0
    fi
    sleep 1
    return 0
  fi
  log_warn "watch: inotify-tools not installed; polling every 10s (install inotify-tools for instant reaction)"
  local last current
  last=$(stat -c %Y "$target" 2>/dev/null || echo 0)
  while true; do
    sleep 10
    current=$(stat -c %Y "$target" 2>/dev/null || echo 0)
    [[ "$current" != "$last" ]] && return 0
  done
}

pi_watch_loop() {
  [[ "${PI_WATCH:-0}" == "1" ]] || return 0
  local target
  target=$(_pi_watch_target)
  log_info "watch: monitoring $target for changes (Ctrl-C to exit)"
  # Strip --watch from the child argv so the re-run does one pass and
  # exits instead of recursing into another watcher.
  local -a child_argv=()
  local arg
  for arg in "${PI_WATCH_ARGV[@]}"; do
    [[ "$arg" == "--watch" ]] && continue
    child_argv+=("$arg")
  done
  local last_trigger=0 now
  while true; do
    _pi_watch_wait "$target" || {
      log_error "watch: cannot monitor $target; exiting watch loop"
      return 1
    }
    now=$(date +%s)
    (( now - last_trigger < 2 )) && continue
    last_trigger=$now
    log_info "watch: $target changed; re-running"
    "$0" "${child_argv[@]}" || log_warn "watch: re-run exited non-zero"
  done
}
