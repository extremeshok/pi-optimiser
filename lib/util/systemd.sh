# ======================================================================
# lib/util/systemd.sh — systemd unit helpers
#
# Functions: unit_exists, unit_disable_now, unit_mask, remount_path,
#            pi_mark_daemon_reload_needed, pi_daemon_reload_if_needed,
#            pi_daemon_reload_now, write_systemd_unit
# Globals (read/write): PI_DAEMON_RELOAD_PENDING
# ======================================================================

# Write a systemd unit / drop-in (body on stdin) the safe way, replacing
# the `record_created; cat > file; chmod 0644` pattern that was copied —
# with subtle variations — across the unit-writing tasks. Does, in order:
#   1. record_created  — so --undo can remove (or restore) the file;
#   2. _pi_atomic_write — stage .tmp + fsync + os.replace, so a power
#      loss mid-write can never leave systemd an unparseable unit;
#   3. chmod 0644       — units must be world-readable, not umask-derived;
#   4. pi_mark_daemon_reload_needed — batch the reload to end of run.
# A task that must `systemctl enable --now` the unit within the SAME run
# should call pi_daemon_reload_now afterwards (it reloads immediately and
# clears the pending flag, avoiding a duplicate end-of-run reload).
# Returns non-zero only if the atomic write fails.
write_systemd_unit() {
  local path=$1
  record_created "$path"
  _pi_atomic_write "$path" || return 1
  chmod 0644 "$path" 2>/dev/null || true
  pi_mark_daemon_reload_needed
}

# Mark that a task modified a systemd unit and a daemon-reload is needed.
# Tasks should call this instead of `systemctl daemon-reload` directly so
# the reload is batched to a single invocation at end of run. A fresh
# install with ~8 tasks writing units was previously doing 8 reloads
# (~100ms each on an SD-card Pi) — now it's one.
pi_mark_daemon_reload_needed() {
  # shellcheck disable=SC2034  # consumed by pi_daemon_reload_if_needed
  PI_DAEMON_RELOAD_PENDING=1
}

# Run daemon-reload only if at least one task marked it pending. Called
# by the main task loop once after all tasks have run. Safe to call
# multiple times — subsequent calls are no-ops until something is
# re-marked.
pi_daemon_reload_if_needed() {
  if [[ ${PI_DAEMON_RELOAD_PENDING:-0} -eq 1 ]]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    PI_DAEMON_RELOAD_PENDING=0
  fi
}

# Force an immediate daemon-reload. Used by the legacy `systemctl
# daemon-reload` call sites that have been migrated but still need
# the reload to happen before subsequent `systemctl enable --now`
# calls within the same task. Most call sites can use
# pi_mark_daemon_reload_needed instead.
pi_daemon_reload_now() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  PI_DAEMON_RELOAD_PENDING=0
}

# Check whether a systemd unit definition exists.
unit_exists() {
  systemctl list-unit-files "$1" >/dev/null 2>&1
}

# Disable and stop a systemd unit if present.
unit_disable_now() {
  local unit=$1
  if ! unit_exists "$unit"; then
    return
  fi
  if ! systemctl disable --now "$unit" >/dev/null 2>&1; then
    log_warn "Unable to disable $unit"
  else
    log_info "Disabled $unit"
  fi
}

# Mask a systemd unit to prevent activation.
unit_mask() {
  local unit=$1
  if ! unit_exists "$unit"; then
    return
  fi
  if ! systemctl mask "$unit" >/dev/null 2>&1; then
    log_warn "Unable to mask $unit"
  else
    log_info "Masked $unit"
  fi
}

# Attempt to remount a path to apply updated options.
remount_path() {
  local path=$1
  if mountpoint -q "$path"; then
    if ! mount -o remount "$path" >/dev/null 2>&1; then
      mount "$path" >/dev/null 2>&1 || true
    fi
  fi
}
