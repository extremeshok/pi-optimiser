# >>> pi-task
# id: oc_conservative
# version: 1.2.0
# description: Apply a safe per-model overclock (Pi 5 2.8 GHz, Pi 4 1.75 GHz)
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 1
# flags: --overclock-conservative
# gate_var: REQUEST_OC_CONSERVATIVE
# reboot_required: true
# <<< pi-task

pi_task_register oc_conservative \
  description="Apply a safe per-model overclock (Pi 5 2.8 GHz, Pi 4 1.75 GHz)" \
  category=hardware-clocks \
  version=1.2.0 \
  default_enabled=0 \
  power_sensitive=1 \
  flags="--overclock-conservative" \
  gate_var=REQUEST_OC_CONSERVATIVE \
  reboot_required=1

# Single source of truth for the per-model overclock plan, consumed by
# both run_oc_conservative and pi_preview_oc_conservative so --diff can
# never drift from what is written (and to the correct per-model section).
# Prints: <section>\n<profile>\n<entry>...   (no output = unsupported model)
# Each profile is routed into its own config.txt section so booting the
# SD card on a different Pi model can't apply a value the silicon can't
# sustain.
_oc_conservative_plan() {
  if is_pi5; then
    printf '%s\n' pi5 pi5_2800mhz over_voltage_delta=30000 arm_freq=2800 gpu_freq=950
  elif is_pi400; then
    printf '%s\n' pi400 pi400_conservative arm_freq=2000 gpu_freq=600
  elif is_pi4; then
    printf '%s\n' pi4 pi4_conservative arm_freq=1750 gpu_freq=600
  elif is_pi3; then
    printf '%s\n' pi3 pi3_conservative arm_freq=1400 gpu_freq=500
  elif is_pizero2; then
    printf '%s\n' pi02 pi_zero2_conservative arm_freq=1200 gpu_freq=500
  fi
}

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
  # Refuse to push clocks higher on a Pi that has *historically* hit
  # undervoltage / throttle / soft-temp since last boot. Clearing that
  # flag requires a reboot on a known-good PSU, so the operator can
  # retry after addressing the root cause.
  if [[ ${POWER_HISTORY_CLEAN:-1} -eq 0 ]]; then
    log_warn "Skipping conservative overclock: vcgencmd reports historical undervoltage/throttle since boot"
    log_warn "Reboot on a known-good 5V/5A PSU and re-run once 'vcgencmd get_throttled' reads 0x0"
    pi_skip_reason "historical throttle since boot"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot apply conservative overclock"
    pi_skip_reason "config.txt missing"
    return 2
  fi

  local -a plan=()
  mapfile -t plan < <(_oc_conservative_plan)
  if (( ${#plan[@]} == 0 )); then
    log_info "Conservative overclock not supported on model ${SYSTEM_MODEL:-unknown}"
    pi_skip_reason "model unsupported"
    return 2
  fi
  local section=${plan[0]} profile=${plan[1]}
  local -a entries=("${plan[@]:2}")

  backup_file "$CONFIG_TXT_FILE"
  # apply_config_entries records each entry under overclock.<safe_key>
  # (prefix "overclock"), matching the prior per-entry state shape.
  local rc=0
  apply_config_entries "overclock" "$section" "${entries[@]}" || rc=$?
  case $rc in
    0)
      write_json_field "$CONFIG_OPTIMISER_STATE" "overclock.profile" "$profile"
      log_info "Conservative overclock profile applied: $profile"
      ;;
    1) log_info "Overclock profile already present" ;;
    *) log_warn "One or more overclock entries failed to apply" ;;
  esac
}

pi_preview_oc_conservative() {
  [[ ${REQUEST_OC_CONSERVATIVE:-0} -eq 0 ]] && return 0
  local -a plan=()
  mapfile -t plan < <(_oc_conservative_plan)
  (( ${#plan[@]} == 0 )) && return 0
  pi_preview_apply_entries --section "${plan[0]}" "${plan[@]:2}"
}
