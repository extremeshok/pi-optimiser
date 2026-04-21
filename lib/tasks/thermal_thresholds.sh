# >>> pi-task
# id: thermal_thresholds
# version: 1.1.0
# description: Set firmware thermal limits (temp_limit, initial_turbo)
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 1
# flags: --temp-limit,--temp-soft-limit,--initial-turbo
# gate_var: THERMAL_THRESHOLDS_SET
# reboot_required: true
# <<< pi-task

pi_task_register thermal_thresholds \
  description="Set firmware thermal limits (temp_limit, initial_turbo)" \
  category=hardware-clocks \
  version=1.1.0 \
  default_enabled=0 \
  power_sensitive=1 \
  flags="--temp-limit,--temp-soft-limit,--initial-turbo" \
  gate_var=THERMAL_THRESHOLDS_SET \
  reboot_required=1

run_thermal_thresholds() {
  if [[ ${THERMAL_THRESHOLDS_SET:-0} -eq 0 ]]; then
    log_info "Thermal thresholds not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot tune thermals"
    pi_skip_reason "config.txt missing"
    return 2
  fi
  # Defense-in-depth: the CLI validates these, but the YAML path
  # also sets them and a malformed value like "85\nenable_uart=1"
  # would inject a second firmware directive into config.txt. Reject
  # anything that isn't a bare integer before writing.
  if [[ -n ${TEMP_LIMIT:-} && ! $TEMP_LIMIT =~ ^[0-9]{1,3}$ ]]; then
    log_error "Invalid TEMP_LIMIT '$TEMP_LIMIT' (expected integer)"
    return 1
  fi
  if [[ -n ${TEMP_SOFT_LIMIT:-} && ! $TEMP_SOFT_LIMIT =~ ^[0-9]{1,3}$ ]]; then
    log_error "Invalid TEMP_SOFT_LIMIT '$TEMP_SOFT_LIMIT' (expected integer)"
    return 1
  fi
  if [[ -n ${INITIAL_TURBO:-} && ! $INITIAL_TURBO =~ ^[0-9]{1,3}$ ]]; then
    log_error "Invalid INITIAL_TURBO '$INITIAL_TURBO' (expected integer)"
    return 1
  fi
  backup_file "$CONFIG_TXT_FILE"
  local rc changed=0
  if [[ -n ${TEMP_LIMIT:-} ]]; then
    rc=0
    ensure_config_key_value "temp_limit=$TEMP_LIMIT" "$CONFIG_TXT_FILE" || rc=$?
    [[ $rc -eq 0 ]] && { log_info "Set temp_limit=$TEMP_LIMIT"; changed=1; }
  fi
  if [[ -n ${TEMP_SOFT_LIMIT:-} ]]; then
    rc=0
    ensure_config_key_value "temp_soft_limit=$TEMP_SOFT_LIMIT" "$CONFIG_TXT_FILE" || rc=$?
    [[ $rc -eq 0 ]] && { log_info "Set temp_soft_limit=$TEMP_SOFT_LIMIT"; changed=1; }
  fi
  if [[ -n ${INITIAL_TURBO:-} ]]; then
    rc=0
    ensure_config_key_value "initial_turbo=$INITIAL_TURBO" "$CONFIG_TXT_FILE" || rc=$?
    [[ $rc -eq 0 ]] && { log_info "Set initial_turbo=$INITIAL_TURBO"; changed=1; }
  fi
  if [[ $changed -eq 0 ]]; then
    log_info "Thermal thresholds already match requested values"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "hardware.thermal.temp_limit" "${TEMP_LIMIT:-unset}"
  write_json_field "$CONFIG_OPTIMISER_STATE" "hardware.thermal.temp_soft_limit" "${TEMP_SOFT_LIMIT:-unset}"
  write_json_field "$CONFIG_OPTIMISER_STATE" "hardware.thermal.initial_turbo" "${INITIAL_TURBO:-unset}"
}

pi_preview_thermal_thresholds() {
  [[ ${THERMAL_THRESHOLDS_SET:-0} -eq 0 ]] && return 0
  local -a entries=()
  [[ -n ${TEMP_LIMIT:-} ]] && entries+=("temp_limit=$TEMP_LIMIT")
  [[ -n ${TEMP_SOFT_LIMIT:-} ]] && entries+=("temp_soft_limit=$TEMP_SOFT_LIMIT")
  [[ -n ${INITIAL_TURBO:-} ]] && entries+=("initial_turbo=$INITIAL_TURBO")
  (( ${#entries[@]} > 0 )) && pi_preview_apply_entries "${entries[@]}"
}
