# >>> pi-task
# id: boot_config
# version: 1.2.0
# description: Apply recommended display settings (KMS overlay, HDMI hotplug)
# category: display
# default_enabled: 1
# power_sensitive: 1
# reboot_required: true
# <<< pi-task

pi_task_register boot_config \
  description="Apply recommended display settings (KMS overlay, HDMI hotplug)" \
  category=display \
  version=1.2.0 \
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
  #
  # gpu_mem=320 is a display-centric split — raises GPU RAM for
  # dual-display KMS. Don't set it on headless runs
  # (KEEP_SCREEN_BLANKING=1 or HEADLESS_GPU_MEM=1), since those
  # paths want the RAM back for the CPU.
  if ! is_pi5; then
    entries+=(
      "framebuffer_depth=32"
      "framebuffer_ignore_alpha=1"
      "arm_boost=1"
    )
    if [[ ${KEEP_SCREEN_BLANKING:-0} -eq 0 && ${HEADLESS_GPU_MEM:-0} -eq 0 ]]; then
      entries+=("gpu_mem=320")
    fi
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
    pi_skip_reason "config.txt missing"
    return 2
  fi
  backup_file "$CONFIG_TXT_FILE"
  local -a entries=()
  mapfile -t entries < <(_boot_config_entries)
  # apply_config_entries upserts key=value entries (gpu_mem, disable_overscan,
  # dtparam=audio=on, framebuffer_*) by key so an existing raspi-config value
  # is REPLACED rather than leaving a second conflicting line, while the bare
  # `dtoverlay=vc4-kms-v3d` keeps additive whole-line semantics.
  local rc=0
  apply_config_entries "boot_config" all "${entries[@]}" || rc=$?
  case $rc in
    0) log_info "Boot config tuned for Raspberry Pi desktop display" ;;
    1) log_info "Boot config already matched recommended defaults" ;;
    *) log_warn "One or more boot config entries failed to apply" ;;
  esac
}

pi_preview_boot_config() {
  pi_supports_kms_overlays || return 0
  local -a entries=()
  mapfile -t entries < <(_boot_config_entries)
  pi_preview_apply_entries "${entries[@]}"
}
