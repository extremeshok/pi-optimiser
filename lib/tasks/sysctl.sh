# >>> pi-task
# id: sysctl
# version: 1.2.0
# description: Tune kernel memory and network settings for server/desktop use
# category: system
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register sysctl \
  description="Tune kernel memory and network settings for server/desktop use" \
  category=system \
  version=1.2.0 \
  default_enabled=1

run_sysctl() {
  cat <<'CFG' > "$SYSCTL_CONF_FILE"
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_writeback_centisecs = 6000
vm.dirty_expire_centisecs = 12000
fs.inotify.max_user_watches = 524288
fs.file-max = 2097152
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.netdev_max_backlog = 4096
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# TCP BBR + fq qdisc — Google's production default since ~2017. Better
# throughput and lower latency on lossy / high-RTT links than the
# kernel's CUBIC default. bbr requires fq (or fq_codel, but fq is the
# upstream recommendation) as the queueing discipline. No-op on older
# kernels that lack BBR; the task logs a warning in that case.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
CFG
  sysctl -p "$SYSCTL_CONF_FILE" >/dev/null 2>&1 || log_warn "sysctl reload encountered an issue"
  # Verify BBR actually loaded — if the kernel lacks tcp_bbr, the
  # control value falls back to whatever was set before. Surface that
  # so operators on very old kernels know their BBR line is decorative.
  local active_cc
  active_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
  if [[ "$active_cc" != "bbr" ]]; then
    log_warn "TCP BBR not active (kernel reports congestion_control=$active_cc); upgrade the kernel to enable"
  fi
}
