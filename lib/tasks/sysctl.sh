# >>> pi-task
# id: sysctl
# version: 1.1.0
# description: Tune kernel memory and writeback behaviour
# category: system
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register sysctl \
  description="Tune kernel memory and writeback behaviour" \
  category=system \
  version=1.1.0 \
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
CFG
  sysctl -p "$SYSCTL_CONF_FILE" >/dev/null 2>&1 || log_warn "sysctl reload encountered an issue"
}
