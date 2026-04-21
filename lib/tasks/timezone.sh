# >>> pi-task
# id: timezone
# version: 1.2.0
# description: Set the system timezone
# category: system
# default_enabled: 0
# power_sensitive: 0
# flags: --timezone
# gate_var: REQUESTED_TIMEZONE
# <<< pi-task

pi_task_register timezone \
  description="Set the system timezone" \
  category=system \
  version=1.2.0 \
  default_enabled=0 \
  flags="--timezone" \
  gate_var=REQUESTED_TIMEZONE

run_timezone() {
  if [[ -z "$REQUESTED_TIMEZONE" ]]; then
    log_info "No timezone requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  # REQUESTED_TIMEZONE is interpolated into a symlink target
  # (/etc/localtime -> /usr/share/zoneinfo/$tz) and written into
  # /etc/timezone. Reject path traversal ('..'), absolute paths, and
  # shell metacharacters before the file-exists check so a crafted
  # value can't point /etc/localtime at an attacker-staged file.
  if ! validate_timezone_name "$REQUESTED_TIMEZONE"; then
    log_error "Invalid timezone '$REQUESTED_TIMEZONE' (expected IANA zone like Europe/London)"
    return 1
  fi
  if [[ ! -f "/usr/share/zoneinfo/$REQUESTED_TIMEZONE" ]]; then
    log_error "Timezone '$REQUESTED_TIMEZONE' not found under /usr/share/zoneinfo"
    return 1
  fi
  # Back up both files before either branch rewrites them. timedatectl
  # updates /etc/timezone and /etc/localtime (a symlink) atomically, so
  # we need snapshots on disk for --undo to restore either one. cp -a
  # inside backup_file keeps /etc/localtime's symlink semantics intact.
  [[ -f /etc/timezone ]] && backup_file /etc/timezone
  [[ -e /etc/localtime || -L /etc/localtime ]] && backup_file /etc/localtime
  if command -v timedatectl >/dev/null 2>&1; then
    if ! timedatectl set-timezone "$REQUESTED_TIMEZONE" >/dev/null 2>&1; then
      log_error "timedatectl failed to set timezone to $REQUESTED_TIMEZONE"
      return 1
    fi
  else
    ln -sf "/usr/share/zoneinfo/$REQUESTED_TIMEZONE" /etc/localtime
    echo "$REQUESTED_TIMEZONE" > /etc/timezone
  fi
  log_info "System timezone set to $REQUESTED_TIMEZONE"
  write_json_field "$CONFIG_OPTIMISER_STATE" "timezone.name" "$REQUESTED_TIMEZONE"
}
