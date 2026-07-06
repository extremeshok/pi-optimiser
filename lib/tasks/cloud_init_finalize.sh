# >>> pi-task
# id: cloud_init_finalize
# version: 1.0.0
# description: Disable cloud-init after first-boot provisioning
# category: system
# default_enabled: 0
# power_sensitive: 0
# flags: --cloud-init-finalize
# gate_var: CLOUD_INIT_FINALIZE
# <<< pi-task

pi_task_register cloud_init_finalize \
  description="Disable cloud-init after first-boot provisioning" \
  category=system \
  version=1.0.0 \
  default_enabled=0 \
  flags="--cloud-init-finalize" \
  gate_var=CLOUD_INIT_FINALIZE

run_cloud_init_finalize() {
  if [[ ${CLOUD_INIT_FINALIZE:-0} -eq 0 ]]; then
    log_info "cloud-init finalization not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi

  if [[ ! -d /etc/cloud && ! -x /usr/bin/cloud-init && ! -x /usr/bin/cloud-init-per ]]; then
    log_info "cloud-init does not appear to be installed; skipping"
    pi_skip_reason "cloud-init missing"
    return 2
  fi

  mkdir -p /etc/cloud
  local marker="/etc/cloud/cloud-init.disabled"
  if [[ -f "$marker" ]]; then
    log_info "cloud-init is already disabled by $marker"
    write_json_field "$CONFIG_OPTIMISER_STATE" "system.cloud_init" "disabled"
    return 0
  fi

  record_created "$marker"
  printf 'disabled by pi-optimiser after first-boot provisioning\n' > "$marker"
  chmod 0644 "$marker"
  log_info "cloud-init disabled for future boots via $marker"
  log_info "Remove $marker to re-enable cloud-init."
  write_json_field "$CONFIG_OPTIMISER_STATE" "system.cloud_init" "disabled"
}
