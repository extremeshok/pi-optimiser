# >>> pi-task
# id: ipv6_disable
# version: 1.0.0
# description: Disable IPv6 via sysctl (opt-in; IPv6 is usually safer left on)
# category: network
# default_enabled: 0
# power_sensitive: 0
# flags: --disable-ipv6
# gate_var: DISABLE_IPV6
# <<< pi-task

pi_task_register ipv6_disable \
  description="Disable IPv6 via sysctl (opt-in; IPv6 is usually safer left on)" \
  category=network \
  version=1.0.0 \
  default_enabled=0 \
  flags="--disable-ipv6" \
  gate_var=DISABLE_IPV6

# Some tightly-scoped deployments (legacy firewalls, IPv6-unfriendly
# ISPs, compliance rules) need IPv6 off. Most operators should leave
# it alone — disabling it silently breaks local-link mDNS, split-
# horizon DNS, and anything that uses link-local addresses. Kept opt-
# in for that reason. Applied at runtime + persisted via a dedicated
# sysctl file so --undo can reverse it cleanly.
run_ipv6_disable() {
  if [[ ${DISABLE_IPV6:-0} -eq 0 ]]; then
    log_info "IPv6 disable not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  local conf=/etc/sysctl.d/98-pi-optimiser-ipv6.conf
  backup_file "$conf"
  cat <<'CFG' > "$conf"
# Written by pi-optimiser::ipv6_disable. Remove this file + run
# `sysctl --system` to re-enable IPv6 without a reboot.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
CFG
  chmod 644 "$conf"
  if sysctl -p "$conf" >/dev/null 2>&1; then
    log_info "IPv6 disabled via $conf (effective immediately)"
    write_json_field "$CONFIG_OPTIMISER_STATE" "network.ipv6" "disabled"
    return 0
  fi
  log_warn "sysctl -p $conf failed; IPv6 may still be partially enabled"
  return 1
}
