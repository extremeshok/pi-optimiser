# >>> pi-task
# id: disable_swap
# version: 1.1.0
# description: Turn off the default swap file (best with 2 GB+ RAM)
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register disable_swap \
  description="Turn off the default swap file (best with 2 GB+ RAM)" \
  category=storage \
  version=1.1.0 \
  default_enabled=1

run_disable_swap() {
  local result=0
  if command -v dphys-swapfile >/dev/null 2>&1; then
    if ! dphys-swapfile swapoff >/dev/null 2>&1; then
      log_warn "dphys-swapfile swapoff reported an issue"
      result=1
    else
      log_info "Disabled swap via dphys-swapfile"
    fi
  fi
  if unit_exists dphys-swapfile.service; then
    if ! systemctl disable --now dphys-swapfile.service >/dev/null 2>&1; then
      log_warn "Unable to disable dphys-swapfile.service"
      result=1
    else
      log_info "Disabled dphys-swapfile.service"
    fi
  fi
  if [[ -f /etc/dphys-swapfile ]]; then
    sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=0/' /etc/dphys-swapfile
  fi
  swapoff -a >/dev/null 2>&1 || true
  return $result
}
