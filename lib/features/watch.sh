# ======================================================================
# lib/features/watch.sh — re-run pi-optimiser when config.yaml changes
#
# `--watch` runs the main pipeline once, then blocks on inotifywait(1)
# against the config.yaml path and re-execs the whole script (same argv
# minus --watch, to prevent runaway recursion) each time the file
# changes. Requires inotify-tools; falls back to a polling loop if it's
# missing so the feature is usable on slim images too.
#
# Two-second debounce groups editor save-temp / rename bursts so saving
# from vim / nano doesn't trigger three back-to-back runs.
#
# Functions: pi_watch_loop
# Globals (read): PI_WATCH, PI_CONFIG_FILE, PI_CONFIG_DEFAULT,
#                 SCRIPT_DIR, BASH_SOURCE
# ======================================================================

_pi_watch_target() {
  if [[ -n "${PI_CONFIG_FILE:-}" ]]; then
    printf '%s\n' "$PI_CONFIG_FILE"
    return 0
  fi
  printf '%s\n' "${PI_CONFIG_DEFAULT:-/etc/pi-optimiser/config.yaml}"
}

# Block until the config file changes. Returns 0 on change, 1 if we
# cannot watch at all (so the caller can exit instead of spinning).
_pi_watch_wait() {
  local target=$1
  # If the file hasn't been created yet, watch its parent directory for
  # a matching create event instead of erroring out of inotifywait.
  if [[ ! -f "$target" ]]; then
    local parent
    parent=$(dirname "$target")
    mkdir -p "$parent" 2>/dev/null || true
    if command -v inotifywait >/dev/null 2>&1; then
      while true; do
        inotifywait -qq --event create,moved_to "$parent" 2>/dev/null || return 1
        [[ -f "$target" ]] && return 0
      done
    fi
    while [[ ! -f "$target" ]]; do sleep 5; done
    return 0
  fi
  if command -v inotifywait >/dev/null 2>&1; then
    # --event close_write,move,delete catches editor rename-on-save and
    # straight in-place writes. -qq suppresses all output.
    if inotifywait -qq --event close_write,move,delete,create "$target" 2>/dev/null; then
      return 0
    fi
    # inotifywait can fail if the parent dir is gone or the file was
    # replaced atomically; wait a moment and re-arm.
    sleep 1
    return 0
  fi
  log_warn "watch: inotify-tools not installed; polling every 10s (install inotify-tools for instant reaction)"
  local last_mtime current
  last_mtime=$(stat -c %Y "$target" 2>/dev/null || echo 0)
  while true; do
    sleep 10
    current=$(stat -c %Y "$target" 2>/dev/null || echo 0)
    if [[ "$current" != "$last_mtime" ]]; then
      return 0
    fi
  done
}

# Re-exec self with the original argv minus --watch (so we don't recurse
# when the child reaches pi_watch_loop again). Called from main() after
# the first non-watch pass completes.
pi_watch_loop() {
  if [[ "${PI_WATCH:-0}" != "1" ]]; then
    return 0
  fi
  local target
  target=$(_pi_watch_target)
  if [[ ! -f "$target" ]]; then
    log_warn "watch: $target does not exist yet; waiting for it to appear"
  fi
  log_info "watch: monitoring $target for changes (Ctrl-C to exit)"
  # Strip --watch from the argv we'll re-exec with. We keep everything
  # else so --yes / --profile / --only still hold across reruns.
  local -a child_argv=()
  local arg skip=0
  for arg in "${PI_WATCH_ARGV[@]}"; do
    if [[ $skip -eq 1 ]]; then skip=0; continue; fi
    if [[ "$arg" == "--watch" ]]; then continue; fi
    child_argv+=("$arg")
  done
  # Debounce burst-write events from editors. Two close_write events in
  # a row inside 2 s collapse into one re-run.
  local last_trigger=0 now
  while true; do
    _pi_watch_wait "$target" || {
      log_error "watch: cannot monitor $target; exiting watch loop"
      return 1
    }
    now=$(date +%s)
    if (( now - last_trigger < 2 )); then
      continue
    fi
    last_trigger=$now
    log_info "watch: $target changed; re-running"
    # Use a child process so a task failure doesn't kill the watcher.
    # $0 is the launcher symlink (or the current checkout); invoking it
    # picks up any self-updates too.
    if [[ ${#child_argv[@]} -gt 0 ]]; then
      "$0" "${child_argv[@]}" || log_warn "watch: re-run exited non-zero"
    else
      "$0" || log_warn "watch: re-run exited non-zero"
    fi
  done
}
