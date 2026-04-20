# >>> pi-task
# id: ufw_firewall
# version: 1.0.0
# description: Install and enable UFW with deny-in / allow-out + SSH exception
# category: security
# default_enabled: 0
# power_sensitive: 0
# flags: --install-firewall
# gate_var: INSTALL_FIREWALL
# <<< pi-task

pi_task_register ufw_firewall \
  description="Install and enable UFW with deny-in / allow-out + SSH exception" \
  category=security \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-firewall" \
  gate_var=INSTALL_FIREWALL

# Detect the actual SSH listen port from sshd_config; fall back to 22.
# Multiple Port lines → take the first (matches sshd's default behaviour
# for inbound selection in the absence of ListenAddress restrictions).
_ufw_ssh_port() {
  local port=""
  if [[ -r /etc/ssh/sshd_config ]]; then
    port=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
  fi
  echo "${port:-22}"
}

run_ufw_firewall() {
  if [[ ${INSTALL_FIREWALL:-0} -eq 0 ]]; then
    log_info "UFW firewall not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  ensure_packages ufw
  if ! command -v ufw >/dev/null 2>&1; then
    log_warn "ufw not installed after apt attempt; skipping"
    return 1
  fi

  # Set defaults before opening any holes. ufw --force skips the
  # interactive confirmation that would otherwise block a non-TTY run.
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  # Always keep SSH reachable on the port sshd actually listens on —
  # locking ourselves out of a headless Pi is the worst-case UX here.
  local ssh_port
  ssh_port=$(_ufw_ssh_port)
  ufw allow "${ssh_port}/tcp" comment "pi-optimiser: SSH" >/dev/null 2>&1 || true

  # Let ICMP through (default allows echo anyway but set it explicitly
  # so the rule is obvious in `ufw status`).
  ufw allow proto icmp comment "pi-optimiser: ping" >/dev/null 2>&1 || true

  # Trust in-mesh traffic from Tailscale / WireGuard when those are
  # installed — otherwise ufw would silently break the VPN. The
  # interface-name match only fires if the interface actually exists.
  if ip -br link show tailscale0 2>/dev/null | grep -q tailscale0; then
    ufw allow in on tailscale0 comment "pi-optimiser: tailscale mesh" >/dev/null 2>&1 || true
  fi
  local wg_iface
  for wg_iface in /sys/class/net/wg*; do
    [[ -d "$wg_iface" ]] || continue
    ufw allow in on "$(basename "$wg_iface")" comment "pi-optimiser: wireguard" >/dev/null 2>&1 || true
  done

  if ufw --force enable >/dev/null 2>&1; then
    systemctl enable --now ufw >/dev/null 2>&1 || true
    log_info "UFW enabled (deny in / allow out; SSH on ${ssh_port}/tcp)"
    write_json_field "$CONFIG_OPTIMISER_STATE" "firewall.ufw" "enabled"
    write_json_field "$CONFIG_OPTIMISER_STATE" "firewall.ssh_port" "$ssh_port"
    return 0
  fi
  log_warn "ufw enable failed; firewall not active"
  return 1
}
