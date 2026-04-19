# >>> pi-task
# id: eeprom_refresh
# version: 1.1.0
# description: Refresh the Raspberry Pi bootloader EEPROM
# category: firmware-eeprom
# default_enabled: 0
# power_sensitive: 1
# flags: --eeprom-update
# gate_var: EEPROM_UPDATE
# reboot_required: true
# <<< pi-task

pi_task_register eeprom_refresh \
  description="Refresh the Raspberry Pi bootloader EEPROM" \
  category=firmware-eeprom \
  version=1.1.0 \
  default_enabled=0 \
  power_sensitive=1 \
  flags="--eeprom-update" \
  gate_var=EEPROM_UPDATE \
  reboot_required=1

run_eeprom_refresh() {
  if [[ $EEPROM_UPDATE -eq 0 ]]; then
    log_info "Bootloader EEPROM update not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if ! command -v rpi-eeprom-update >/dev/null 2>&1; then
    log_warn "rpi-eeprom-update not available; skipping"
    pi_skip_reason "rpi-eeprom-update missing"
    return 2
  fi
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Network unavailable; skipping rpi-eeprom-update"
    pi_skip_reason "network unavailable"
    return 2
  fi

  local out rc=0
  out=$(rpi-eeprom-update -a 2>&1) || rc=$?
  if [[ $rc -eq 0 ]]; then
    log_info "rpi-eeprom-update -a completed; reboot required to apply new EEPROM"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.last_update" "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
    return 0
  fi
  log_warn "rpi-eeprom-update returned exit code $rc"
  log_warn "Output: $out"
  return 1
}
