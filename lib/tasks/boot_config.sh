# >>> pi-task
# id: boot_config
# version: 1.1.0
# description: Tune /boot/firmware/config.txt for kiosk display stability
# category: display
# default_enabled: 1
# power_sensitive: 1
# reboot_required: true
# <<< pi-task

pi_task_register boot_config \
  description="Tune /boot/firmware/config.txt for kiosk display stability" \
  category=display \
  version=1.1.0 \
  default_enabled=1 \
  power_sensitive=1 \
  reboot_required=1

# Shared list of config.txt entries that apply to every KMS-capable Pi
# (Pi 4 and Pi 5). Assembled by _boot_config_entries so run + preview
# stay in sync; Pi-4-only entries are appended when the model matches.
_boot_config_entries() {
  local -a entries=(
    "dtoverlay=vc4-kms-v3d"
    "disable_overscan=1"
    "hdmi_force_hotplug=1"
    "dtparam=audio=on"
  )
  # Pi 5 uses unified memory (gpu_mem ignored), runs at rated clock
  # (arm_boost no-op), and ships KMS-only (legacy framebuffer_* keys
  # have no effect). Keep these on Pi 4 and older only.
  if ! is_pi5; then
    entries+=(
      "gpu_mem=320"
      "framebuffer_depth=32"
      "framebuffer_ignore_alpha=1"
      "arm_boost=1"
    )
  fi
  printf '%s\n' "${entries[@]}"
}

run_boot_config() {
  if ! pi_supports_kms_overlays; then
    log_info "Skipping boot config tuning (model ${SYSTEM_MODEL:-unknown} does not support vc4-kms presets)"
    pi_skip_reason "model unsupported"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_info "config.txt not present; skipping boot config tuning"
    return 0
  fi
  backup_file "$CONFIG_TXT_FILE"
  local -a entries=()
  mapfile -t entries < <(_boot_config_entries)
  local applied=0
  local entry rc safe_key
  for entry in "${entries[@]}"; do
    if ensure_config_line "$entry"; then
      log_info "Applied $entry to config.txt"
      safe_key=${entry//=/_}
      write_json_field "$CONFIG_OPTIMISER_STATE" "boot_config.${safe_key}" "$entry"
      applied=1
    else
      rc=$?
      if [[ $rc -gt 1 ]]; then
        log_warn "Failed to ensure $entry in config.txt"
      fi
    fi
  done
  if [[ $applied -eq 1 ]]; then
    log_info "Boot config tuned for Raspberry Pi desktop display"
  else
    log_info "Boot config already matched recommended defaults"
  fi
}

pi_preview_boot_config() {
  pi_supports_kms_overlays || return 0
  local target=${CONFIG_TXT_FILE:-/boot/firmware/config.txt}
  local entry
  while IFS= read -r entry; do
    ensure_config_line "$entry" "$target" >/dev/null 2>&1 || true
  done < <(_boot_config_entries)
}
