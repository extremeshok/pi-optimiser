# >>> pi-task
# id: firmware_update
# version: 1.2.0
# description: Install the latest Raspberry Pi firmware (rpi-update; cutting edge)
# category: firmware-eeprom
# default_enabled: 0
# power_sensitive: 1
# flags: --firmware-update
# gate_var: FIRMWARE_UPDATE
# reboot_required: conditional
# refresh_days: manual
# <<< pi-task

pi_task_register firmware_update \
  description="Install the latest Raspberry Pi firmware (rpi-update; cutting edge)" \
  category=firmware-eeprom \
  version=1.2.0 \
  default_enabled=0 \
  power_sensitive=1 \
  flags="--firmware-update" \
  gate_var=FIRMWARE_UPDATE \
  reboot_required=conditional \
  refresh_days=manual

run_firmware_update() {
  if [[ $FIRMWARE_UPDATE -eq 0 ]]; then
    log_info "Firmware update via rpi-update not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if ! command -v rpi-update >/dev/null 2>&1; then
    log_warn "rpi-update not installed; skipping firmware update"
    pi_skip_reason "rpi-update missing"
    return 2
  fi
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Network unavailable; skipping rpi-update"
    pi_skip_reason "network unavailable"
    return 2
  fi

  log_info "Running rpi-update non-interactively (SKIP_WARNING=1)"
  # Pipe 'y' into stdin as a belt-and-suspenders guard for any future prompts.
  # Disable pipefail so yes(1) getting SIGPIPE doesn't mask rpi-update's exit
  # code; `|| rpi_update_rc=$?` prevents `set -e` from firing on a real failure
  # and captures rpi-update's status.
  local rpi_update_rc=0 output=""
  set +o pipefail
  output=$(yes y | SKIP_WARNING=1 rpi-update 2>&1) || rpi_update_rc=$?
  set -o pipefail
  if [[ $rpi_update_rc -eq 0 ]]; then
    local now
    now=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')
    write_json_field "$CONFIG_OPTIMISER_STATE" "firmware.last_check" "$now"
    if grep -Eiq 'already.*up[ -]?to[ -]?date|up[ -]?to[ -]?date|no update' <<<"$output"; then
      log_info "rpi-update checked successfully; firmware is already current"
      return 0
    fi
    log_info "rpi-update completed; reboot required to activate new firmware"
    write_json_field "$CONFIG_OPTIMISER_STATE" "firmware.last_update" "$now"
    pi_mark_reboot_required firmware_update
    return 0
  fi
  log_warn "rpi-update returned exit code $rpi_update_rc"
  return 1
}
