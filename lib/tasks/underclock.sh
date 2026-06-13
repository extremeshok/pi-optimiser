# >>> pi-task
# id: underclock
# version: 1.0.0
# description: Apply a low-power underclock profile
# category: hardware-clocks
# default_enabled: 0
# power_sensitive: 0
# flags: --underclock
# gate_var: REQUEST_UNDERCLOCK
# reboot_required: true
# <<< pi-task

pi_task_register underclock \
  description="Apply a low-power underclock profile" \
  category=hardware-clocks \
  version=1.0.0 \
  default_enabled=0 \
  flags="--underclock" \
  gate_var=REQUEST_UNDERCLOCK \
  reboot_required=1

# Single source of truth for the per-model underclock plan, consumed by
# both run_underclock and pi_preview_underclock so --diff matches what is
# written (and to the correct per-model section). Prints:
# <section>\n<profile>\n<entry>...   (no output = unsupported model).
_underclock_plan() {
  if is_pi5; then
    printf '%s\n' pi5 pi5_underclock arm_freq=1800 gpu_freq=700
  elif is_pi4; then
    printf '%s\n' pi4 pi4_underclock arm_freq=1200 gpu_freq=400
  elif is_pi3; then
    printf '%s\n' pi3 pi3_underclock arm_freq=1000 gpu_freq=300
  elif is_pizero2; then
    printf '%s\n' pi02 pi_zero2_underclock arm_freq=900 gpu_freq=300
  fi
}

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

  local -a plan=()
  mapfile -t plan < <(_underclock_plan)
  if (( ${#plan[@]} == 0 )); then
    log_info "Underclock not supported on model ${SYSTEM_MODEL:-unknown}"
    pi_skip_reason "model unsupported"
    return 2
  fi
  local section=${plan[0]} profile=${plan[1]}
  local -a entries=("${plan[@]:2}")

  backup_file "$CONFIG_TXT_FILE"
  local rc=0
  apply_config_entries "underclock" "$section" "${entries[@]}" || rc=$?

  # Switch scaling governor to powersave to pair with the lower clocks.
  local g
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -w "$g" ]] || continue
    echo powersave > "$g" 2>/dev/null || true
  done

  case $rc in
    0)
      write_json_field "$CONFIG_OPTIMISER_STATE" "underclock.profile" "$profile"
      log_info "Underclock profile applied: $profile"
      ;;
    1) log_info "Underclock profile already present" ;;
    *) log_warn "One or more underclock entries failed to apply" ;;
  esac
}

pi_preview_underclock() {
  [[ ${REQUEST_UNDERCLOCK:-0} -eq 0 ]] && return 0
  [[ ${REQUEST_OC_CONSERVATIVE:-0} -eq 1 ]] && return 0
  local -a plan=()
  mapfile -t plan < <(_underclock_plan)
  (( ${#plan[@]} == 0 )) && return 0
  pi_preview_apply_entries --section "${plan[0]}" "${plan[@]:2}"
}
