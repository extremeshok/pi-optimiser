# >>> pi-task
# id: wifi_bt_power
# version: 1.1.0
# description: Keep Wi-Fi awake; optionally disable Bluetooth
# category: network
# default_enabled: 0
# flags: --wifi-powersave-off,--disable-bluetooth
# gate_var: WIFI_POWERSAVE_OFF
# <<< pi-task

pi_task_register wifi_bt_power \
  description="Keep Wi-Fi awake; optionally disable Bluetooth" \
  category=network \
  version=1.1.0 \
  default_enabled=0 \
  flags="--wifi-powersave-off,--disable-bluetooth" \
  gate_var=WIFI_POWERSAVE_OFF

run_wifi_bt_power() {
  local did=0

  if [[ ${WIFI_POWERSAVE_OFF:-0} -eq 1 ]]; then
    mkdir -p /etc/systemd/system
    local wifi_unit=/etc/systemd/system/pi-optimiser-wifi-powersave-off.service
    record_created "$wifi_unit"
    cat <<'CFG' > "$wifi_unit"
[Unit]
Description=Disable Wi-Fi power save (pi-optimiser)
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for d in /sys/class/net/wlan*; do iface=$(basename "$d"); /usr/sbin/iw dev "$iface" set power_save off >/dev/null 2>&1 || true; done'

[Install]
WantedBy=multi-user.target
CFG
    # Pin the unit to 0644 so a loose operator umask can't leave it
    # group/world-writable — the unit runs as root on every boot.
    chmod 0644 "$wifi_unit" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now pi-optimiser-wifi-powersave-off.service >/dev/null 2>&1 || log_warn "Unable to enable wifi-powersave-off unit"
    log_info "Wi-Fi power save disabled (service enabled)"
    did=1
  fi

  if [[ ${DISABLE_BLUETOOTH:-0} -eq 1 ]]; then
    unit_disable_now hciuart.service
    unit_disable_now bluetooth.service
    unit_mask bluetooth.service
    if [[ -f "$CONFIG_TXT_FILE" ]]; then
      backup_file "$CONFIG_TXT_FILE"
      local rc=0
      ensure_config_line "dtoverlay=disable-bt" "$CONFIG_TXT_FILE" || rc=$?
      [[ $rc -eq 0 ]] && log_info "Added dtoverlay=disable-bt to config.txt"
    fi
    log_info "Bluetooth disabled (service masked, overlay set)"
    did=1
  fi

  if [[ $did -eq 0 ]]; then
    log_info "No Wi-Fi/BT power tweaks requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "network.wifi_powersave_off" "${WIFI_POWERSAVE_OFF:-0}"
  write_json_field "$CONFIG_OPTIMISER_STATE" "network.bluetooth_disabled" "${DISABLE_BLUETOOTH:-0}"
}
