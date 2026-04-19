# >>> pi-task
# id: oc_conservative
# version: 1.2.0
# description: Apply Raspberry Pi overclock profile (Pi 5/500 2.8 GHz)
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 1
# flags: --overclock-conservative
# gate_var: REQUEST_OC_CONSERVATIVE
# reboot_required: true
# <<< pi-task

pi_task_register oc_conservative \
  description="Apply Raspberry Pi overclock profile (Pi 5/500 2.8 GHz)" \
  category=hardware-clocks \
  version=1.2.0 \
  default_enabled=0 \
  power_sensitive=1 \
  flags="--overclock-conservative" \
  gate_var=REQUEST_OC_CONSERVATIVE \
  reboot_required=1

run_oc_conservative() {
  if [[ $REQUEST_OC_CONSERVATIVE -eq 0 ]]; then
    log_info "Conservative overclock not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ $POWER_HEALTHY -eq 0 ]]; then
    log_warn "Skipping conservative overclock because preflight reported power/thermal issues"
    pi_skip_reason "preflight power/thermal issues"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot apply conservative overclock"
    pi_skip_reason "config.txt missing"
    return 2
  fi

  local -a entries=()
  local profile=""
  if is_pi5; then
    entries=(
      "over_voltage_delta=30000"
      "arm_freq=2800"
      "gpu_freq=950"
    )
    profile="pi5_2800mhz"
  elif is_pi400; then
    entries=(
      "arm_freq=2000"
      "gpu_freq=600"
    )
    profile="pi400_conservative"
  elif is_pi4; then
    entries=(
      "arm_freq=1750"
      "gpu_freq=600"
    )
    profile="pi4_conservative"
  elif is_pi3; then
    entries=(
      "arm_freq=1400"
      "gpu_freq=500"
    )
    profile="pi3_conservative"
  elif is_pizero2; then
    entries=(
      "arm_freq=1200"
      "gpu_freq=500"
    )
    profile="pi_zero2_conservative"
  else
    log_info "Conservative overclock not supported on model ${SYSTEM_MODEL:-unknown}"
    pi_skip_reason "model unsupported"
    return 2
  fi

  backup_file "$CONFIG_TXT_FILE"
  local applied=0 entry safe_key rc
  for entry in "${entries[@]}"; do
    rc=0
    ensure_config_key_value "$entry" "$CONFIG_TXT_FILE" || rc=$?
    if [[ $rc -eq 0 ]]; then
      log_info "Applied $entry to config.txt"
      safe_key=${entry//=/_}
      write_json_field "$CONFIG_OPTIMISER_STATE" "overclock.${safe_key}" "$entry"
      applied=1
    elif [[ $rc -gt 1 ]]; then
      log_warn "Failed to apply $entry to config.txt"
    fi
  done
  if [[ $applied -eq 1 ]]; then
    write_json_field "$CONFIG_OPTIMISER_STATE" "overclock.profile" "$profile"
    log_info "Conservative overclock profile applied: $profile"
  else
    log_info "Overclock profile already present"
  fi
}
