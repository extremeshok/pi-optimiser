# >>> pi-task
# id: wireguard
# version: 1.0.0
# description: Install WireGuard VPN tools (configure /etc/wireguard yourself)
# category: network
# default_enabled: 0
# flags: --install-wireguard
# gate_var: INSTALL_WIREGUARD
# <<< pi-task

pi_task_register wireguard \
  description="Install WireGuard VPN tools (configure /etc/wireguard yourself)" \
  category=network \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-wireguard" \
  gate_var=INSTALL_WIREGUARD

run_wireguard() {
  if [[ ${INSTALL_WIREGUARD:-0} -eq 0 ]]; then
    log_info "WireGuard not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ ${INSTALL_TAILSCALE:-0} -eq 1 && ${ALLOW_BOTH_VPN:-0} -eq 0 ]]; then
    log_warn "Tailscale and WireGuard both requested; pass --allow-both-vpn to override"
    pi_skip_reason "conflicts with tailscale"
    return 2
  fi
  ensure_packages wireguard wireguard-tools
  # Create the standard config directory with tight perms; we don't drop
  # keys or interfaces here — that's user-specific configuration.
  install -d -m 700 /etc/wireguard
  log_info "WireGuard tooling installed; configure /etc/wireguard/<iface>.conf to bring up an interface"
  write_json_field "$CONFIG_OPTIMISER_STATE" "network.wireguard" "installed"
}
