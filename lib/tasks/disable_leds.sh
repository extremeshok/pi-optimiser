# >>> pi-task
# id: disable_leds
# version: 1.0.0
# description: Turn off the activity, power, and ethernet LEDs (headless/rack)
# category: display
# default_enabled: 0
# power_sensitive: 0
# flags: --disable-leds
# gate_var: DISABLE_LEDS
# reboot_required: true
# <<< pi-task

pi_task_register disable_leds \
  description="Turn off the activity, power, and ethernet LEDs (headless/rack)" \
  category=display \
  version=1.0.0 \
  default_enabled=0 \
  flags="--disable-leds" \
  gate_var=DISABLE_LEDS \
  reboot_required=1

# Settings applied to /boot/firmware/config.txt:
#   act_led_trigger=none + act_led_activelow=off  — green activity LED
#   pwr_led_trigger=none + pwr_led_activelow=off  — red power LED (Pi 4+)
#   eth_led0=4 + eth_led1=4                       — both ethernet jack LEDs
#
# Saves ~5-15 mA total and stops the strobe in a server rack. Applies
# to Pi 4/400/5/500; older models silently ignore the unknown
# dtparams.
# Single source of truth for the LED dtparams, consumed by both
# run_disable_leds and pi_preview_disable_leds so --diff can never
# drift from what is actually written.
_disable_leds_entries() {
  printf '%s\n' \
    "dtparam=act_led_trigger=none" \
    "dtparam=act_led_activelow=off" \
    "dtparam=pwr_led_trigger=none" \
    "dtparam=pwr_led_activelow=off" \
    "dtparam=eth_led0=4" \
    "dtparam=eth_led1=4"
}

run_disable_leds() {
  if [[ ${DISABLE_LEDS:-0} -eq 0 ]]; then
    log_info "LED disable not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot disable LEDs"
    pi_skip_reason "config.txt missing"
    return 2
  fi
  backup_file "$CONFIG_TXT_FILE"
  local -a entries=()
  mapfile -t entries < <(_disable_leds_entries)
  local rc=0
  apply_config_entries "" all "${entries[@]}" || rc=$?
  case $rc in
    0)
      log_info "Status LEDs disabled (effective after reboot)"
      write_json_field "$CONFIG_OPTIMISER_STATE" "display.leds_disabled" "true"
      ;;
    1) log_info "LED disables already present" ;;
    *) log_warn "One or more LED disables failed to apply" ;;
  esac
}

pi_preview_disable_leds() {
  [[ ${DISABLE_LEDS:-0} -eq 0 ]] && return 0
  local -a entries=()
  mapfile -t entries < <(_disable_leds_entries)
  pi_preview_apply_entries "${entries[@]}"
}
