# >>> pi-task
# id: pcie_gen3
# version: 1.0.0
# description: Enable Pi 5 PCIe Gen 3 for faster NVMe HATs (unofficial)
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 1
# flags: --pcie-gen3
# gate_var: INSTALL_PCIE_GEN3
# reboot_required: true
# <<< pi-task

pi_task_register pcie_gen3 \
  description="Enable Pi 5 PCIe Gen 3 for faster NVMe HATs (unofficial)" \
  category=hardware-clocks \
  version=1.0.0 \
  default_enabled=0 \
  power_sensitive=1 \
  flags="--pcie-gen3" \
  gate_var=INSTALL_PCIE_GEN3 \
  reboot_required=1

run_pcie_gen3() {
  if [[ ${INSTALL_PCIE_GEN3:-0} -eq 0 ]]; then
    log_info "PCIe Gen 3 not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if ! is_pi5; then
    log_info "PCIe Gen 3 only applies to Pi 5/500; skipping"
    pi_skip_reason "model unsupported"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot set PCIe gen"
    pi_skip_reason "config.txt missing"
    return 2
  fi
  backup_file "$CONFIG_TXT_FILE"
  local rc=0
  ensure_config_key_value "dtparam=pciex1_gen=3" "$CONFIG_TXT_FILE" || rc=$?
  if [[ $rc -eq 0 ]]; then
    log_info "Enabled PCIe Gen 3 in config.txt (unofficial; active after reboot)"
  elif [[ $rc -eq 1 ]]; then
    log_info "PCIe Gen 3 already set"
  else
    log_warn "Failed to set dtparam=pciex1_gen=3"
    return 1
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "hardware.pcie_gen3" "enabled"
}

pi_preview_pcie_gen3() {
  [[ ${INSTALL_PCIE_GEN3:-0} -eq 0 ]] && return 0
  is_pi5 || return 0
  pi_preview_apply_entries "dtparam=pciex1_gen=3"
}
