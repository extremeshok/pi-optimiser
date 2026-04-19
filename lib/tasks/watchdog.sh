# >>> pi-task
# id: watchdog
# version: 1.1.0
# description: Enable hardware watchdog when --enable-watchdog is provided
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 1
# flags: --enable-watchdog
# gate_var: INSTALL_WATCHDOG
# reboot_required: true
# <<< pi-task

pi_task_register watchdog \
  description="Enable hardware watchdog when --enable-watchdog is provided" \
  category=hardware-clocks \
  version=1.1.0 \
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
  mkdir -p "$watchdog_dir"
  cat <<'CFG' > "$watchdog_dir/99-pi-optimiser-watchdog.conf"
[Manager]
RuntimeWatchdogSec=15
ShutdownWatchdogSec=10min
CFG
  systemctl daemon-reload >/dev/null 2>&1 || true
  log_info "Configured systemd RuntimeWatchdogSec=15; active after reboot"
  write_json_field "$CONFIG_OPTIMISER_STATE" "watchdog.enabled" "true"
}
