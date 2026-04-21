# >>> pi-task
# id: disable_services
# version: 1.2.0
# description: Stop non-essential background services (ModemManager, Avahi, openipmi)
# category: system
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register disable_services \
  description="Stop non-essential background services (ModemManager, Avahi, openipmi)" \
  category=system \
  version=1.2.0 \
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

  # openipmi has no IPMI hardware on a Pi; mask it so it never attempts
  # to start (disabling alone isn't enough — it can still be pulled in
  # as a dependency of ipmitool, which prometheus-node-exporter-collectors
  # depends on for IPMI metric collection).
  if unit_exists openipmi.service; then
    unit_mask openipmi.service
  fi
}
