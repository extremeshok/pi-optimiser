# >>> pi-task
# id: node_exporter
# version: 1.0.0
# description: Export system metrics for Prometheus on :9100 (node-exporter)
# category: network
# default_enabled: 0
# flags: --install-node-exporter
# gate_var: INSTALL_NODE_EXPORTER
# <<< pi-task

pi_task_register node_exporter \
  description="Export system metrics for Prometheus on :9100 (node-exporter)" \
  category=network \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-node-exporter" \
  gate_var=INSTALL_NODE_EXPORTER

run_node_exporter() {
  if [[ ${INSTALL_NODE_EXPORTER:-0} -eq 0 ]]; then
    log_info "node_exporter not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  ensure_packages prometheus-node-exporter
  systemctl enable --now prometheus-node-exporter >/dev/null 2>&1 \
    || log_warn "Unable to enable prometheus-node-exporter"
  log_info "prometheus-node-exporter enabled on port 9100"
  write_json_field "$CONFIG_OPTIMISER_STATE" "network.node_exporter" "enabled"
}
