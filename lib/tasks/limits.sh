# >>> pi-task
# id: limits
# version: 1.1.0
# description: Raise per-user file-descriptor and process limits
# category: system
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register limits \
  description="Raise per-user file-descriptor and process limits" \
  category=system \
  version=1.1.0 \
  default_enabled=1

run_limits() {
  local limits_dir system_dir user_dir
  limits_dir=$(dirname "$LIMITS_CONF_FILE")
  mkdir -p "$limits_dir"
  cat <<'CFG' > "$LIMITS_CONF_FILE"
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
* soft nproc 32768
* hard nproc 32768
root soft nproc 32768
root hard nproc 32768
CFG
  log_info "Configured $LIMITS_CONF_FILE"

  system_dir=$(dirname "$SYSTEMD_SYSTEM_LIMITS")
  mkdir -p "$system_dir"
  cat <<'CFG' > "$SYSTEMD_SYSTEM_LIMITS"
[Manager]
DefaultLimitNOFILE=65535
DefaultLimitNPROC=32768
CFG
  log_info "Configured $SYSTEMD_SYSTEM_LIMITS"

  user_dir=$(dirname "$SYSTEMD_USER_LIMITS")
  mkdir -p "$user_dir"
  cat <<'CFG' > "$SYSTEMD_USER_LIMITS"
[Manager]
DefaultLimitNOFILE=65535
DefaultLimitNPROC=32768
CFG
  log_info "Configured $SYSTEMD_USER_LIMITS"

  systemctl daemon-reload >/dev/null 2>&1 || true
  if unit_exists systemd-logind.service; then
    systemctl restart systemd-logind >/dev/null 2>&1 || log_warn "systemd-logind restart encountered an issue"
  fi
}
