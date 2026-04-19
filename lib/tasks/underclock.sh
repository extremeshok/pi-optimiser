# >>> pi-task
# id: underclock
# version: 1.0.0
# description: Apply an underclocked / low-power profile (inverse of oc_conservative)
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 0
# flags: --underclock
# gate_var: REQUEST_UNDERCLOCK
# reboot_required: true
# <<< pi-task

pi_task_register underclock \
  description="Apply an underclocked / low-power profile (inverse of oc_conservative)" \
  category=hardware-clocks \
  version=1.0.0 \
  default_enabled=0 \
  flags="--underclock" \
  gate_var=REQUEST_UNDERCLOCK \
  reboot_required=1

run_underclock() {
  if [[ ${REQUEST_UNDERCLOCK:-0} -eq 0 ]]; then
    log_info "Underclock not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ ${REQUEST_OC_CONSERVATIVE:-0} -eq 1 ]]; then
    log_warn "--underclock conflicts with --overclock-conservative; dropping underclock"
    pi_skip_reason "conflicts with overclock"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot underclock"
    pi_skip_reason "config.txt missing"
    return 2
  fi

  local -a entries=()
  local profile=""
  if is_pi5; then
    entries=("arm_freq=1800" "gpu_freq=700")
    profile="pi5_underclock"
  elif is_pi4; then
    entries=("arm_freq=1200" "gpu_freq=400")
    profile="pi4_underclock"
  elif is_pi3; then
    entries=("arm_freq=1000" "gpu_freq=300")
    profile="pi3_underclock"
  elif is_pizero2; then
    entries=("arm_freq=900" "gpu_freq=300")
    profile="pi_zero2_underclock"
  else
    log_info "Underclock not supported on model ${SYSTEM_MODEL:-unknown}"
    pi_skip_reason "model unsupported"
    return 2
  fi

  backup_file "$CONFIG_TXT_FILE"
  local entry rc applied=0 safe_key
  for entry in "${entries[@]}"; do
    rc=0
    ensure_config_key_value "$entry" "$CONFIG_TXT_FILE" || rc=$?
    if [[ $rc -eq 0 ]]; then
      log_info "Applied $entry to config.txt"
      safe_key=${entry//=/_}
      write_json_field "$CONFIG_OPTIMISER_STATE" "underclock.${safe_key}" "$entry"
      applied=1
    elif [[ $rc -gt 1 ]]; then
      log_warn "Failed to apply $entry"
    fi
  done

  # Switch scaling governor to powersave to pair with the lower clocks.
  local g
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -w "$g" ]] || continue
    echo powersave > "$g" 2>/dev/null || true
  done

  if [[ $applied -eq 1 ]]; then
    write_json_field "$CONFIG_OPTIMISER_STATE" "underclock.profile" "$profile"
    log_info "Underclock profile applied: $profile"
  else
    log_info "Underclock profile already present"
  fi
}

pi_preview_underclock() {
  [[ ${REQUEST_UNDERCLOCK:-0} -eq 0 ]] && return 0
  [[ ${REQUEST_OC_CONSERVATIVE:-0} -eq 1 ]] && return 0
  local -a entries=()
  if is_pi5; then
    entries=("arm_freq=1800" "gpu_freq=700")
  elif is_pi4; then
    entries=("arm_freq=1200" "gpu_freq=400")
  elif is_pi3; then
    entries=("arm_freq=1000" "gpu_freq=300")
  elif is_pizero2; then
    entries=("arm_freq=900" "gpu_freq=300")
  else
    return 0
  fi
  pi_preview_apply_entries "${entries[@]}"
}
