# >>> pi-task
# id: full_upgrade
# version: 1.0.0
# description: Full system upgrade (update + full-upgrade + autoremove + autoclean)
# category: system
# default_enabled: 1
# power_sensitive: 0
# always_run: true
# <<< pi-task

pi_task_register full_upgrade \
  description="Full system upgrade (update + full-upgrade + autoremove + autoclean)" \
  category=system \
  version=1.0.0 \
  default_enabled=1 \
  always_run=1

run_full_upgrade() {
  apt_wait_for_lock 60 || {
    log_warn "apt/dpkg lock held; skipping full upgrade"
    pi_skip_reason "apt lock busy"
    return 2
  }

  log_info "Running apt-get update"
  local rc=0
  DEBIAN_FRONTEND=noninteractive apt-get update -q || rc=$?
  if [[ $rc -ne 0 ]]; then
    log_warn "apt-get update failed (rc=$rc)"
    return 1
  fi
  # shellcheck disable=SC2034  # read by apt_update_once to skip redundant update
  APT_UPDATED=1

  log_info "Running apt-get full-upgrade"
  DEBIAN_FRONTEND=noninteractive \
    apt-get full-upgrade -y \
      -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confold" || {
    log_warn "apt-get full-upgrade failed"
    return 1
  }

  log_info "Running apt-get autoremove"
  DEBIAN_FRONTEND=noninteractive apt-get autoremove -y || true

  log_info "Running apt-get autoclean"
  DEBIAN_FRONTEND=noninteractive apt-get autoclean -y || true
}
