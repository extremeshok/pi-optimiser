# >>> pi-task
# id: fstrim
# version: 1.1.0
# description: Enable weekly fstrim.timer for SSD/NVMe TRIM
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register fstrim \
  description="Enable weekly fstrim.timer for SSD/NVMe TRIM" \
  category=storage \
  version=1.1.0 \
  default_enabled=1

run_fstrim() {
  if ! systemctl list-unit-files fstrim.timer >/dev/null 2>&1; then
    log_info "fstrim.timer unit not available; skipping"
    pi_skip_reason "fstrim.timer missing"
    return 2
  fi
  if ! systemctl enable --now fstrim.timer >/dev/null 2>&1; then
    log_warn "Unable to enable fstrim.timer"
    return 1
  fi
  log_info "Enabled fstrim.timer for weekly SSD/NVMe TRIM"
  write_json_field "$CONFIG_OPTIMISER_STATE" "fstrim.enabled" "true"
}
