# >>> pi-task
# id: dns_cache
# version: 1.0.0
# description: Run a local DNS cache (systemd-resolved) for faster lookups
# category: network
# default_enabled: 0
# flags: --enable-dns-cache
# gate_var: ENABLE_DNS_CACHE
# <<< pi-task

pi_task_register dns_cache \
  description="Run a local DNS cache (systemd-resolved) for faster lookups" \
  category=network \
  version=1.0.0 \
  default_enabled=0 \
  flags="--enable-dns-cache" \
  gate_var=ENABLE_DNS_CACHE

run_dns_cache() {
  if [[ ${ENABLE_DNS_CACHE:-0} -eq 0 ]]; then
    log_info "DNS cache not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if ! unit_exists systemd-resolved.service; then
    ensure_packages systemd-resolved
  fi
  local conf_dir=/etc/systemd/resolved.conf.d
  mkdir -p "$conf_dir"
  cat <<'CFG' > "$conf_dir/99-pi-optimiser.conf"
[Resolve]
DNSStubListener=yes
Cache=yes
CacheFromLocalhost=no
DNSOverTLS=opportunistic
CFG
  systemctl enable --now systemd-resolved >/dev/null 2>&1 || log_warn "Unable to enable systemd-resolved"

  # Point /etc/resolv.conf at the stub so clients use the cache.
  if [[ -L /etc/resolv.conf ]]; then
    local current
    current=$(readlink -f /etc/resolv.conf)
    if [[ $current != /run/systemd/resolve/stub-resolv.conf ]]; then
      ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
      log_info "Pointed /etc/resolv.conf at systemd-resolved stub"
    fi
  else
    backup_file /etc/resolv.conf
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    log_info "Replaced /etc/resolv.conf with systemd-resolved stub symlink"
  fi
  systemctl restart systemd-resolved >/dev/null 2>&1 || true
  write_json_field "$CONFIG_OPTIMISER_STATE" "network.dns_cache" "systemd-resolved"
}
