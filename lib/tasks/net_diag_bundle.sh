# >>> pi-task
# id: net_diag_bundle
# version: 1.0.0
# description: Install network-diagnostic tools (nmap, iperf3, tcpdump, traceroute)
# category: packages
# default_enabled: 0
# flags: --install-net-diag
# gate_var: INSTALL_NET_DIAG
# <<< pi-task

pi_task_register net_diag_bundle \
  description="Install network-diagnostic tools (nmap, iperf3, tcpdump, traceroute)" \
  category=packages \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-net-diag" \
  gate_var=INSTALL_NET_DIAG

run_net_diag_bundle() {
  if [[ ${INSTALL_NET_DIAG:-0} -eq 0 ]]; then
    log_info "Network diagnostics bundle not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  ensure_packages nmap iperf3 tcpdump traceroute
  log_info "Network diagnostics bundle installed"
  write_json_field "$CONFIG_OPTIMISER_STATE" "packages.net_diag" "installed"
}
