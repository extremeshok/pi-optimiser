# >>> pi-task
# id: tmpfs_tmp
# version: 1.1.0
# description: Mount /tmp in RAM (tmpfs) to reduce disk writes
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register tmpfs_tmp \
  description="Mount /tmp in RAM (tmpfs) to reduce disk writes" \
  category=storage \
  version=1.1.0 \
  default_enabled=1

run_tmpfs_tmp() {
  if grep -E "^\s*tmpfs\s+/tmp\s+tmpfs" /etc/fstab >/dev/null; then
    log_info "/tmp already defined as tmpfs"
    if mountpoint -q /tmp && findmnt -n /tmp | grep -q "tmpfs"; then
      return 0
    fi
  fi
  backup_file /etc/fstab
  if ! grep -E "^\s*tmpfs\s+/tmp\s+tmpfs" /etc/fstab >/dev/null; then
    echo "$TMPFS_ENTRY" >> /etc/fstab
    log_info "Appended tmpfs entry for /tmp"
  fi
  if mountpoint -q /tmp; then
    mount -o remount /tmp >/dev/null 2>&1 || true
  else
    mount /tmp >/dev/null 2>&1 || true
  fi
}
