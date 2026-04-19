# >>> pi-task
# id: smartmontools
# version: 1.0.0
# description: Monitor NVMe/SSD health (smartmontools + smartd)
# category: packages
# default_enabled: 0
# flags: --install-smartmontools
# gate_var: INSTALL_SMARTMONTOOLS
# <<< pi-task

pi_task_register smartmontools \
  description="Monitor NVMe/SSD health (smartmontools + smartd)" \
  category=packages \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-smartmontools" \
  gate_var=INSTALL_SMARTMONTOOLS

run_smartmontools() {
  if [[ ${INSTALL_SMARTMONTOOLS:-0} -eq 0 ]]; then
    log_info "smartmontools not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  ensure_packages smartmontools
  systemctl enable --now smartd >/dev/null 2>&1 || log_warn "Unable to enable smartd"
  log_info "smartmontools installed; smartd enabled"
  write_json_field "$CONFIG_OPTIMISER_STATE" "packages.smartmontools" "installed"
}
