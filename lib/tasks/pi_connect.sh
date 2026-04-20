# >>> pi-task
# id: pi_connect
# version: 1.0.0
# description: Install Raspberry Pi Connect for browser-based remote access
# category: integrations
# default_enabled: 0
# power_sensitive: 0
# flags: --install-pi-connect
# gate_var: INSTALL_PI_CONNECT
# <<< pi-task

pi_task_register pi_connect \
  description="Install Raspberry Pi Connect for browser-based remote access" \
  category=integrations \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-pi-connect" \
  gate_var=INSTALL_PI_CONNECT

# Official Raspberry Pi remote-access tool — WebRTC peer-to-peer
# access via a web browser. Requires 64-bit Bookworm (newer beta
# supports 32-bit and back to Pi 1). The package drops a tray icon
# for desktop sessions and a CLI `rpi-connect` for headless.
#
# Pairing is interactive (the user signs in at connect.raspberrypi.com
# and enters a code) so we only install the package here; the operator
# runs `rpi-connect signin` themselves after the task completes.
run_pi_connect() {
  if [[ ${INSTALL_PI_CONNECT:-0} -eq 0 ]]; then
    log_info "Raspberry Pi Connect not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  # Headless-only variant when no display is connected. Autodetect by
  # checking whether a drm connector reports "connected"; default to
  # the full package otherwise so desktop users get the tray icon too.
  local pkg=rpi-connect
  if ! grep -qli connected /sys/class/drm/card*-HDMI*/status 2>/dev/null; then
    pkg=rpi-connect-lite
  fi
  if ! ensure_packages "$pkg"; then
    log_warn "Failed to install $pkg"
    return 1
  fi
  # Enable the user-level service so it starts on next login. For
  # headless setups we also enable the system-wide lingering user
  # service via `loginctl enable-linger` so sessions persist after the
  # user logs out.
  local target_user=${SUDO_USER:-}
  if [[ -z "$target_user" || "$target_user" == "root" ]]; then
    target_user=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
  fi
  if [[ -n "$target_user" ]] && command -v loginctl >/dev/null 2>&1; then
    loginctl enable-linger "$target_user" >/dev/null 2>&1 || true
  fi
  log_info "Installed $pkg; run 'rpi-connect signin' as the user to pair with connect.raspberrypi.com"
  write_json_field "$CONFIG_OPTIMISER_STATE" "integrations.pi_connect" "$pkg"
}
