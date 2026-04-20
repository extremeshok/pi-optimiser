# >>> pi-task
# id: nvme_tune
# version: 1.0.0
# description: Disable NVMe APST for compatibility with Pi 5 NVMe HATs
# category: storage
# default_enabled: 0
# power_sensitive: 0
# flags: --nvme-tune
# gate_var: NVME_TUNE
# reboot_required: true
# <<< pi-task

pi_task_register nvme_tune \
  description="Disable NVMe APST for compatibility with Pi 5 NVMe HATs" \
  category=storage \
  version=1.0.0 \
  default_enabled=0 \
  flags="--nvme-tune" \
  gate_var=NVME_TUNE \
  reboot_required=1

# APST (Autonomous Power State Transitions) is how NVMe drives drop
# into low-power states between bursts. It works well on laptops but a
# number of popular Pi 5 NVMe HAT + drive combos (WD SN770 early
# batches, some Samsung 9xx, a couple of Crucial P3 variants) produce
# "I/O timeout, disable APST" kernel messages and eventually drop the
# device. Setting default_ps_max_latency_us=0 on the kernel command
# line pins the drive at the full-performance state and sidesteps the
# dropout; the cost is marginally higher idle power.
#
# Opt-in: NVMe drives without the compatibility bug benefit from APST,
# so we don't change the default for users who aren't seeing dropouts.
run_nvme_tune() {
  if [[ ${NVME_TUNE:-0} -eq 0 ]]; then
    log_info "NVMe tuning not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ ! -f "$CMDLINE_FILE" ]]; then
    log_warn "cmdline.txt not present; cannot set nvme parameters"
    pi_skip_reason "cmdline.txt missing"
    return 2
  fi
  backup_file "$CMDLINE_FILE"
  local applied=0 rc=0
  cmdline_ensure_token "nvme_core.default_ps_max_latency_us=0" "$CMDLINE_FILE" || rc=$?
  case $rc in
    0) log_info "Added nvme_core.default_ps_max_latency_us=0 to cmdline.txt (active after reboot)"; applied=1 ;;
    1) log_info "NVMe APST disable already present in cmdline.txt" ;;
    *) log_warn "Failed to update cmdline.txt"; return 1 ;;
  esac
  if [[ $applied -eq 1 ]]; then
    write_json_field "$CONFIG_OPTIMISER_STATE" "storage.nvme_apst_disabled" "true"
  fi
}

pi_preview_nvme_tune() {
  [[ ${NVME_TUNE:-0} -eq 0 ]] && return 0
  local target=${CMDLINE_FILE:-/boot/firmware/cmdline.txt}
  cmdline_ensure_token "nvme_core.default_ps_max_latency_us=0" "$target" >/dev/null 2>&1 || true
}
