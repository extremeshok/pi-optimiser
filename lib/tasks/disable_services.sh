# >>> pi-task
# id: disable_services
# version: 1.1.0
# description: Disable non-essential background services
# category: system
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register disable_services \
  description="Disable non-essential background services" \
  category=system \
  version=1.1.0 \
  default_enabled=1

run_disable_services() {
  local -a units=(
    triggerhappy.service
    bluetooth.service
    hciuart.service
    avahi-daemon.service
    cups.service
    rsyslog.service
  )
  local unit
  for unit in "${units[@]}"; do
    if unit_exists "$unit"; then
      unit_disable_now "$unit"
    fi
  done
}
