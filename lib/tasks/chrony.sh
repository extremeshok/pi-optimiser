# >>> pi-task
# id: chrony
# version: 1.0.0
# description: Install chrony for robust time sync on flaky-network Pis
# category: system
# default_enabled: 0
# power_sensitive: 0
# flags: --install-chrony
# gate_var: INSTALL_CHRONY
# <<< pi-task

pi_task_register chrony \
  description="Install chrony for robust time sync on flaky-network Pis" \
  category=system \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-chrony" \
  gate_var=INSTALL_CHRONY

# chrony handles step-corrections, hardware clocks without an RTC, and
# intermittent network links better than systemd-timesyncd — the
# distinguishing case is mobile / 3G-backed / solar-powered IoT Pis
# where wakeups routinely find the clock hours off and timesyncd
# refuses to do a large step. Installing chrony removes
# systemd-timesyncd automatically (they'd otherwise race).
run_chrony() {
  if [[ ${INSTALL_CHRONY:-0} -eq 0 ]]; then
    log_info "chrony not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  ensure_packages chrony
  if ! command -v chronyd >/dev/null 2>&1; then
    log_warn "chronyd not available after apt; skipping"
    return 1
  fi
  # apt usually masks timesyncd when chrony is installed, but be
  # defensive — two time sync daemons fighting over /etc/adjtime is a
  # classic misconfiguration.
  if systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1; then
    systemctl disable --now systemd-timesyncd.service >/dev/null 2>&1 || true
  fi
  systemctl enable --now chrony.service >/dev/null 2>&1 \
    || systemctl enable --now chronyd.service >/dev/null 2>&1 || true
  log_info "chrony enabled as the active time sync daemon"
  write_json_field "$CONFIG_OPTIMISER_STATE" "time.sync_daemon" "chrony"
}
