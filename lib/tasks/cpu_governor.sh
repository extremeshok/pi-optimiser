# >>> pi-task
# id: cpu_governor
# version: 1.2.0
# description: Keep the CPU at full speed (performance governor)
# category: hardware-clocks
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register cpu_governor \
  description="Keep the CPU at full speed (performance governor)" \
  category=hardware-clocks \
  version=1.2.0 \
  default_enabled=1

run_cpu_governor() {
  if [[ ! -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
    log_info "cpufreq not exposed by kernel; skipping governor pinning"
    pi_skip_reason "cpufreq unavailable"
    return 2
  fi

  mkdir -p "$(dirname "$CPU_GOVERNOR_SERVICE")"
  # record_created falls back to backup_file when the path already
  # exists, so --undo still restores a pre-existing operator override.
  record_created "$CPU_GOVERNOR_SERVICE"
  cat <<'CFG' > "$CPU_GOVERNOR_SERVICE"
[Unit]
Description=Pin CPU scaling governor to performance (pi-optimiser)
After=multi-user.target
ConditionPathExists=/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -w "$g" ] && echo performance > "$g" || true; done'

[Install]
WantedBy=multi-user.target
CFG
  chmod 644 "$CPU_GOVERNOR_SERVICE"

  systemctl daemon-reload >/dev/null 2>&1 || true
  # Use enable (not --now) here: the oneshot would try to write to
  # sysfs paths that may not be writable until late in boot, and the
  # manual sysfs loop below already applies the setting for the
  # current boot. The unit exists to re-apply on every subsequent
  # boot via multi-user.target.
  if ! systemctl enable pi-optimiser-cpu-governor.service >/dev/null 2>&1; then
    log_warn "Unable to enable pi-optimiser-cpu-governor.service"
  fi

  local g changed=0
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -w "$g" ]] || continue
    if echo performance > "$g" 2>/dev/null; then
      changed=1
    fi
  done
  if (( changed == 1 )); then
    log_info "CPU scaling governor set to performance"
  else
    log_warn "Unable to write scaling_governor; service will apply on next boot"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "cpu.governor" "performance"
}
