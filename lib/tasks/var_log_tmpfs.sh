# >>> pi-task
# id: var_log_tmpfs
# version: 1.2.0
# description: Keep /var/log in RAM to reduce writes
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register var_log_tmpfs \
  description="Keep /var/log in RAM to reduce writes" \
  category=storage \
  version=1.2.0 \
  default_enabled=1

run_var_log_tmpfs() {
  # Stop journald around the archive/remount so no entries race into the
  # directory we're tearing down. Restart at the end regardless of outcome.
  local journald_stopped=0
  if unit_exists systemd-journald.service; then
    if systemctl stop systemd-journald >/dev/null 2>&1; then
      journald_stopped=1
    else
      log_warn "Could not stop systemd-journald before /var/log remount"
    fi
  fi

  if [[ -d /var/log/journal ]]; then
    if find /var/log/journal -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
      local backup_tar
      backup_tar=/var/log.journal-backup.pi-optimiser.$(date +%Y%m%d%H%M%S).tar.gz
      if tar -czf "$backup_tar" -C /var/log journal >/dev/null 2>&1; then
        log_info "Archived existing journal to $backup_tar"
        rm -rf /var/log/journal/* 2>/dev/null || true
      else
        log_warn "Failed to archive /var/log/journal prior to tmpfs mount"
      fi
    fi
  fi

  if grep -Eq '^tmpfs[[:space:]]+/var/log[[:space:]]+tmpfs' /etc/fstab; then
    log_info "/var/log already configured in fstab"
  else
    backup_file /etc/fstab
    echo "$VAR_LOG_TMPFS_ENTRY" >> /etc/fstab
    log_info "Added tmpfs entry for /var/log"
  fi

  cat <<'CFG' > "$VAR_LOG_TMPFILES"
d /var/log 0755 root root -
d /var/log/apt 0755 root root -
d /var/log/lightdm 0755 root root -
d /var/log/samba 0755 root root -
d /var/log/cups 0755 root lp -
d /var/log/journal 2755 root systemd-journal -
d /var/log/private 0700 root root -
CFG
  log_info "Ensured tmpfiles.d definition for /var/log exists"

  if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "$VAR_LOG_TMPFILES" >/dev/null 2>&1 || true
  fi

  if mountpoint -q /var/log; then
    if ! findmnt -n /var/log | grep -q 'tmpfs'; then
      mount -o remount /var/log >/dev/null 2>&1 || true
    fi
  else
    mount /var/log >/dev/null 2>&1 || true
  fi

  if (( journald_stopped == 1 )); then
    systemctl start systemd-journald >/dev/null 2>&1 || log_warn "Failed to restart systemd-journald"
  fi
}
