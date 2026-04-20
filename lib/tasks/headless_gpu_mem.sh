# >>> pi-task
# id: headless_gpu_mem
# version: 1.0.0
# description: Shrink the GPU memory split to 16 MB on headless Pi 4 and older
# category: display
# default_enabled: 0
# power_sensitive: 0
# flags: --headless-gpu-mem
# gate_var: HEADLESS_GPU_MEM
# reboot_required: true
# <<< pi-task

pi_task_register headless_gpu_mem \
  description="Shrink the GPU memory split to 16 MB on headless Pi 4 and older" \
  category=display \
  version=1.0.0 \
  default_enabled=0 \
  flags="--headless-gpu-mem" \
  gate_var=HEADLESS_GPU_MEM \
  reboot_required=1

# Pi 5 / Pi 500 use a unified memory architecture (VideoCore 7 shares
# SDRAM with the ARM cores via an IOMMU) so the legacy `gpu_mem` split
# is ignored by the firmware — setting it there is a no-op at best
# and confuses readers at worst. Only apply on Pi 4 / Pi 400 / Pi 3 /
# Pi Zero 2 where the firmware honours the split.
#
# 16 MB is the minimum the firmware accepts and hands the remaining
# ~50-240 MB (depending on model) back to the ARM side. Safe only
# when no HDMI work is needed; `boot_config` raises to 320 on
# display-enabled Pis.
run_headless_gpu_mem() {
  if [[ ${HEADLESS_GPU_MEM:-0} -eq 0 ]]; then
    log_info "Headless GPU split not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if is_pi5; then
    log_info "Pi 5 / Pi 500 uses unified memory — gpu_mem is ignored; skipping"
    pi_skip_reason "model unsupported (Pi 5 unified memory)"
    return 2
  fi
  if [[ ! -f "$CONFIG_TXT_FILE" ]]; then
    log_warn "config.txt not present; cannot set gpu_mem"
    pi_skip_reason "config.txt missing"
    return 2
  fi
  backup_file "$CONFIG_TXT_FILE"
  local rc=0
  ensure_config_key_value "gpu_mem=16" "$CONFIG_TXT_FILE" || rc=$?
  case $rc in
    0) log_info "Set gpu_mem=16 in config.txt (reclaims ~50-240 MB for the CPU)" ;;
    1) log_info "gpu_mem=16 already set" ;;
    *) log_warn "Failed to set gpu_mem=16"; return 1 ;;
  esac
  write_json_field "$CONFIG_OPTIMISER_STATE" "display.gpu_mem" "16"
}

pi_preview_headless_gpu_mem() {
  [[ ${HEADLESS_GPU_MEM:-0} -eq 0 ]] && return 0
  is_pi5 && return 0
  pi_preview_apply_entries "gpu_mem=16"
}
