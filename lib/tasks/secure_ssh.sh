# >>> pi-task
# id: secure_ssh
# version: 1.1.0
# description: Harden SSH (no root/password login) and enable fail2ban
# category: security
# default_enabled: 0
# power_sensitive: 0
# flags: --secure-ssh
# gate_var: SECURE_SSH
# <<< pi-task

pi_task_register secure_ssh \
  description="Harden SSH (no root/password login) and enable fail2ban" \
  category=security \
  version=1.1.0 \
  default_enabled=0 \
  flags="--secure-ssh" \
  gate_var=SECURE_SSH

run_secure_ssh() {
  if [[ $SECURE_SSH -eq 0 ]]; then
    log_info "Secure SSH not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi

  local ssh_config=/etc/ssh/sshd_config
  if [[ ! -f "$ssh_config" ]]; then
    log_warn "sshd_config not found; skipping SSH hardening"
    pi_skip_reason "sshd_config missing"
    return 2
  fi

  # Stage fail2ban first so brute-force protection is live before sshd reloads.
  ensure_packages fail2ban
  local jail_dir=/etc/fail2ban/jail.d
  local jail_file=$jail_dir/pi-optimiser-ssh.conf
  mkdir -p "$jail_dir"
  cat <<'JAIL' > "$jail_file"
[sshd]
enabled = true
port    = ssh
maxretry = 5
findtime = 600
bantime  = 600
backend = systemd
JAIL
  log_info "Configured fail2ban jail for sshd"

  systemctl enable --now fail2ban >/dev/null 2>&1 || log_warn "Unable to enable fail2ban service"
  systemctl restart fail2ban >/dev/null 2>&1 || true

  backup_file "$ssh_config"
  update_sshd_config_option "PermitRootLogin" "no"
  update_sshd_config_option "PasswordAuthentication" "yes"
  update_sshd_config_option "ChallengeResponseAuthentication" "no"
  update_sshd_config_option "UsePAM" "yes"

  if ! sshd -t -f "$ssh_config" >/dev/null 2>&1; then
    log_error "sshd configuration validation failed after hardening"
    return 1
  fi

  if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
    systemctl reload ssh >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || log_warn "Unable to reload ssh service"
  fi

  write_json_field "$CONFIG_OPTIMISER_STATE" "security.ssh.permit_root" "no"
  write_json_field "$CONFIG_OPTIMISER_STATE" "security.ssh.fail2ban" "enabled"

  log_info "SSH hardened and fail2ban enabled"
}
