# >>> pi-task
# id: watchdog
# version: 1.2.0
# description: Auto-reboot the Pi if the kernel hangs (hardware watchdog)
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 1
# flags: --enable-watchdog
# gate_var: INSTALL_WATCHDOG
# reboot_required: true
# <<< pi-task

pi_task_register watchdog \
  description="Auto-reboot the Pi if the kernel hangs (hardware watchdog)" \
  category=hardware-clocks \
  version=1.2.0 \
  default_enabled=0 \
  power_sensitive=1 \
  flags="--enable-watchdog" \
  gate_var=INSTALL_WATCHDOG \
  reboot_required=1

run_watchdog() {
  if [[ $INSTALL_WATCHDOG -eq 0 ]]; then
    log_info "Hardware watchdog not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot enable watchdog"
    pi_skip_reason "config.txt missing"
    return 2
  fi
  backup_file "$CONFIG_TXT_FILE"
  local rc=0
  ensure_config_key_value "dtparam=watchdog=on" "$CONFIG_TXT_FILE" || rc=$?
  if [[ $rc -eq 0 ]]; then
    log_info "Enabled dtparam=watchdog=on in config.txt"
  elif [[ $rc -gt 1 ]]; then
    log_warn "Failed to set watchdog dtparam"
  fi

  local watchdog_dir=/etc/systemd/system.conf.d
  local watchdog_conf="$watchdog_dir/99-pi-optimiser-watchdog.conf"
  mkdir -p "$watchdog_dir"
  record_created "$watchdog_conf"
  # Atomic write so a half-written drop-in can't leave systemd's main
  # config in an unparseable state.
  _pi_atomic_write "$watchdog_conf" <<'CFG'
[Manager]
RuntimeWatchdogSec=15
ShutdownWatchdogSec=10min
CFG
  # No immediate start — settings only apply after reboot, so batch
  # the reload with any other unit changes at end of run.
  pi_mark_daemon_reload_needed
  log_info "Configured systemd RuntimeWatchdogSec=15; active after reboot"
  write_json_field "$CONFIG_OPTIMISER_STATE" "watchdog.enabled" "true"
}

pi_preview_watchdog() {
  [[ ${INSTALL_WATCHDOG:-0} -eq 0 ]] && return 0
  pi_preview_apply_entries "dtparam=watchdog=on"
}
