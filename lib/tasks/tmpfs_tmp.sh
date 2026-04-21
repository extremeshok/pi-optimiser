# >>> pi-task
# id: tmpfs_tmp
# version: 1.2.0
# description: Mount /tmp in RAM (tmpfs) to reduce disk writes
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register tmpfs_tmp \
  description="Mount /tmp in RAM (tmpfs) to reduce disk writes" \
  category=storage \
  version=1.2.0 \
  default_enabled=1

run_tmpfs_tmp() {
  # POSIX ERE: use [[:space:]] not \s — portable across grep builds
  # even though GNU grep tolerates \s.
  if grep -E "^[[:space:]]*tmpfs[[:space:]]+/tmp[[:space:]]+tmpfs" /etc/fstab >/dev/null; then
    log_info "/tmp already defined as tmpfs"
    if mountpoint -q /tmp && findmnt -n /tmp | grep -q "tmpfs"; then
      return 0
    fi
  fi
  backup_file /etc/fstab
  # Route through fstab_append_line so we get idempotency by
  # mountpoint, 6-field validation, and an atomic staged write
  # instead of a plain `echo >>` that could leave fstab truncated
  # on power loss. Returns 1 when /tmp already has an entry — not
  # an error, just a no-op.
  local rc=0
  fstab_append_line "$TMPFS_ENTRY" || rc=$?
  case $rc in
    0) log_info "Appended tmpfs entry for /tmp" ;;
    1) : ;; # already present
    *) log_warn "Refusing to append malformed fstab entry for /tmp"; return 1 ;;
  esac
  if mountpoint -q /tmp; then
    mount -o remount /tmp >/dev/null 2>&1 || true
  else
    mount /tmp >/dev/null 2>&1 || true
  fi
}
