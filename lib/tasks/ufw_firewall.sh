# >>> pi-task
# id: ufw_firewall
# version: 1.2.0
# description: Install UFW and open only the ports that active services need
# category: security
# default_enabled: 0
# power_sensitive: 0
# flags: --install-firewall
# gate_var: INSTALL_FIREWALL
# <<< pi-task

pi_task_register ufw_firewall \
  description="Install UFW and open only the ports that active services need" \
  category=security \
  version=1.2.0 \
  default_enabled=0 \
  flags="--install-firewall" \
  gate_var=INSTALL_FIREWALL

# Detect the SSH listen port from sshd_config; fall back to 22.
_ufw_ssh_port() {
  local port=""
  if [[ -r /etc/ssh/sshd_config ]]; then
    port=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
  fi
  echo "${port:-22}"
}

# Build a fingerprint of everything that influences the rule set. When
# the fingerprint differs from the one stored after the last run, the
# main loop clears ufw_firewall's completion marker so the task
# re-reconciles. Keeps the rule list in sync when VPNs or the proxy
# come or go without requiring --force every time.
_ufw_fingerprint() {
  local fp
  fp="ssh=$(_ufw_ssh_port)"
  if ip -br link show tailscale0 2>/dev/null | grep -q tailscale0; then
    fp+=";tailscale"
  fi
  local wg
  for wg in /sys/class/net/wg*; do
    [[ -d "$wg" ]] || continue
    fp+=";$(basename "$wg")"
  done
  # Proxy is active if --proxy-backend is set to a real URL, or if the
  # task's nginx symlink is already in place from a previous run.
  local pb_lower=${PROXY_BACKEND,,}
  case $pb_lower in
    ""|off|disable|disabled|false|no|none|null) : ;;
    *) fp+=";proxy" ;;
  esac
  if [[ -L /etc/nginx/sites-enabled/pi-optimiser-proxy ]]; then
    [[ "$fp" != *";proxy"* ]] && fp+=";proxy"
  fi
  printf '%s\n' "$fp"
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

  # Resolve the SSH port BEFORE touching ufw state. If we can't even
  # determine a port, abort — enabling ufw without an SSH allow rule
  # is the primary remote-lockout scenario this task must prevent.
  local ssh_port
  ssh_port=$(_ufw_ssh_port)
  if ! [[ $ssh_port =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); then
    log_error "Refusing to enable UFW: could not resolve a valid SSH port (got '${ssh_port}')"
    return 1
  fi

  # Wipe the slate before rebuilding. We only own UFW when
  # ufw_firewall is enabled — operators who keep hand-crafted rules
  # on top should skip this task and run ufw directly.
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  # HARD GATE: the SSH allow MUST succeed before anything else. If ufw
  # refuses this rule we bail out rather than risk enabling a firewall
  # that would drop the operator's active session.
  if ! ufw allow "${ssh_port}/tcp" comment "pi-optimiser: SSH" >/dev/null 2>&1; then
    log_error "Refusing to enable UFW: 'ufw allow ${ssh_port}/tcp' failed"
    return 1
  fi
  # ICMPv4 (ping) + ICMPv6 (neighbour discovery, PMTUD). ICMPv6 is
  # required for IPv6 to function at all — without it dual-stack hosts
  # will silently drop v6 traffic.
  ufw allow proto icmp comment "pi-optimiser: ping (v4)" >/dev/null 2>&1 || true
  ufw allow proto ipv6-icmp comment "pi-optimiser: ping (v6)" >/dev/null 2>&1 \
    || ufw allow proto icmpv6 comment "pi-optimiser: ping (v6)" >/dev/null 2>&1 \
    || true

  local opened=()
  # Tailscale: only allow if the interface is actually up.
  if ip -br link show tailscale0 2>/dev/null | grep -q tailscale0; then
    ufw allow in on tailscale0 comment "pi-optimiser: tailscale mesh" >/dev/null 2>&1 || true
    opened+=("tailscale0")
  fi
  # WireGuard: allow each wg* interface that exists.
  local wg_iface name
  for wg_iface in /sys/class/net/wg*; do
    [[ -d "$wg_iface" ]] || continue
    name=$(basename "$wg_iface")
    ufw allow in on "$name" comment "pi-optimiser: wireguard" >/dev/null 2>&1 || true
    opened+=("$name")
  done
  # Proxy (port 80) — detected via explicit PROXY_BACKEND flag OR the
  # existing pi-optimiser-proxy site symlink from a previous run.
  local pb_lower=${PROXY_BACKEND,,}
  local proxy_on=0
  case $pb_lower in
    ""|off|disable|disabled|false|no|none|null) : ;;
    *) proxy_on=1 ;;
  esac
  if [[ -L /etc/nginx/sites-enabled/pi-optimiser-proxy ]]; then
    proxy_on=1
  fi
  if [[ $proxy_on -eq 1 ]]; then
    ufw allow 80/tcp comment "pi-optimiser: proxy (http)" >/dev/null 2>&1 || true
    opened+=("proxy:80")
  fi

  if ufw --force enable >/dev/null 2>&1; then
    systemctl enable --now ufw >/dev/null 2>&1 || true
    log_info "UFW enabled (deny in / allow out; SSH on ${ssh_port}/tcp${opened:+; }${opened[*]})"
    write_json_field "$CONFIG_OPTIMISER_STATE" "firewall.ufw" "enabled"
    write_json_field "$CONFIG_OPTIMISER_STATE" "firewall.ssh_port" "$ssh_port"
    write_json_field "$CONFIG_OPTIMISER_STATE" "firewall.fingerprint" "$(_ufw_fingerprint)"
    return 0
  fi
  log_warn "ufw enable failed; firewall not active"
  return 1
}
