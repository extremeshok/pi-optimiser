# >>> pi-task
# id: pi5_fan
# version: 1.1.0
# description: Apply Pi 5 PWM fan curve when --pi5-fan-profile is provided
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 1
# flags: --pi5-fan-profile
# gate_var: INSTALL_PI5_FAN_PROFILE
# <<< pi-task

pi_task_register pi5_fan \
  description="Apply Pi 5 PWM fan curve when --pi5-fan-profile is provided" \
  category=hardware-clocks \
  version=1.1.0 \
  default_enabled=0 \
  power_sensitive=1 \
  flags="--pi5-fan-profile" \
  gate_var=INSTALL_PI5_FAN_PROFILE

run_pi5_fan() {
  if [[ $INSTALL_PI5_FAN_PROFILE -eq 0 ]]; then
    log_info "Pi 5 fan profile not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if ! is_pi5; then
    log_info "Pi 5 fan profile only applies to Pi 5/500; skipping"
    pi_skip_reason "model unsupported"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot apply fan profile"
    pi_skip_reason "config.txt missing"
    return 2
  fi
  backup_file "$CONFIG_TXT_FILE"
  local -a entries=(
    "dtparam=fan_temp0=50000"
    "dtparam=fan_temp0_hyst=5000"
    "dtparam=fan_temp0_speed=75"
    "dtparam=fan_temp1=60000"
    "dtparam=fan_temp1_hyst=5000"
    "dtparam=fan_temp1_speed=125"
    "dtparam=fan_temp2=67000"
    "dtparam=fan_temp2_hyst=5000"
    "dtparam=fan_temp2_speed=200"
    "dtparam=fan_temp3=75000"
    "dtparam=fan_temp3_hyst=5000"
    "dtparam=fan_temp3_speed=255"
  )
  local entry rc applied=0
  for entry in "${entries[@]}"; do
    rc=0
    ensure_config_key_value "$entry" "$CONFIG_TXT_FILE" || rc=$?
    if [[ $rc -eq 0 ]]; then
      applied=1
    elif [[ $rc -gt 1 ]]; then
      log_warn "Failed to apply $entry"
    fi
  done
  if [[ $applied -eq 1 ]]; then
    log_info "Applied Pi 5 PWM fan curve (50/60/67/75 C)"
  else
    log_info "Pi 5 fan curve already present"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "fan.profile" "pi5_50_60_67_75"
}
