# >>> pi-task
# id: smartmontools
# version: 1.1.0
# description: Monitor NVMe/SSD health (smartmontools + smartd)
# category: packages
# default_enabled: 0
# flags: --install-smartmontools
# gate_var: INSTALL_SMARTMONTOOLS
# <<< pi-task

pi_task_register smartmontools \
  description="Monitor NVMe/SSD health (smartmontools + smartd)" \
  category=packages \
  version=1.1.0 \
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
  # The unit is smartd.service on Debian/Raspberry Pi OS and
  # smartmontools.service on some derivatives. Prefer whichever
  # exists so we don't log a spurious "Unable to enable" warning.
  local smart_unit=""
  if unit_exists smartd.service; then
    smart_unit=smartd.service
  elif unit_exists smartmontools.service; then
    smart_unit=smartmontools.service
  fi
  if [[ -n $smart_unit ]]; then
    systemctl enable --now "$smart_unit" >/dev/null 2>&1 \
      || log_warn "Unable to enable $smart_unit"
  else
    log_warn "No smartd/smartmontools unit found after install"
  fi
  log_info "smartmontools installed; smartd enabled"
  write_json_field "$CONFIG_OPTIMISER_STATE" "packages.smartmontools" "installed"
}
