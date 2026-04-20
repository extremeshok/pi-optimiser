# >>> pi-task
# id: quiet_boot
# version: 1.0.0
# description: Hide the rainbow splash and silence kernel log at boot
# category: display
# default_enabled: 0
# power_sensitive: 0
# flags: --quiet-boot
# gate_var: QUIET_BOOT
# reboot_required: true
# <<< pi-task

pi_task_register quiet_boot \
  description="Hide the rainbow splash and silence kernel log at boot" \
  category=display \
  version=1.0.0 \
  default_enabled=0 \
  flags="--quiet-boot" \
  gate_var=QUIET_BOOT \
  reboot_required=1

# Three changes combine for a clean boot:
#   config.txt:
#     disable_splash=1  — skip the rainbow splash before the kernel
#   cmdline.txt:
#     quiet             — suppress non-critical kernel messages
#     loglevel=3        — KERN_ERR and below only (drops "info")
#
# Opt-in: verbose boot is invaluable for debugging, so we don't want
# this on by default. Kiosks and production rigs usually do.
run_quiet_boot() {
  if [[ ${QUIET_BOOT:-0} -eq 0 ]]; then
    log_info "Quiet boot not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" || ! -f "$CMDLINE_FILE" ]]; then
    log_warn "boot files missing; cannot configure quiet boot"
    pi_skip_reason "boot files missing"
    return 2
  fi
  backup_file "$CONFIG_TXT_FILE"
  backup_file "$CMDLINE_FILE"
  local applied=0 rc

  rc=0; ensure_config_key_value "disable_splash=1" "$CONFIG_TXT_FILE" || rc=$?
  case $rc in
    0) log_info "Disabled rainbow splash in config.txt"; applied=1 ;;
    1) : ;;
    *) log_warn "Failed to write disable_splash=1 to config.txt" ;;
  esac

  rc=0; cmdline_ensure_token "quiet" "$CMDLINE_FILE" || rc=$?
  [[ $rc -eq 0 ]] && { log_info "Added 'quiet' to cmdline.txt"; applied=1; }
  rc=0; cmdline_ensure_token "loglevel=3" "$CMDLINE_FILE" || rc=$?
  [[ $rc -eq 0 ]] && { log_info "Added 'loglevel=3' to cmdline.txt"; applied=1; }

  if [[ $applied -eq 1 ]]; then
    write_json_field "$CONFIG_OPTIMISER_STATE" "display.quiet_boot" "true"
  else
    log_info "Quiet boot already configured"
  fi
}

pi_preview_quiet_boot() {
  [[ ${QUIET_BOOT:-0} -eq 0 ]] && return 0
  local config=${CONFIG_TXT_FILE:-/boot/firmware/config.txt}
  local cmdline=${CMDLINE_FILE:-/boot/firmware/cmdline.txt}
  ensure_config_key_value "disable_splash=1" "$config" >/dev/null 2>&1 || true
  cmdline_ensure_token "quiet" "$cmdline" >/dev/null 2>&1 || true
  cmdline_ensure_token "loglevel=3" "$cmdline" >/dev/null 2>&1 || true
}
