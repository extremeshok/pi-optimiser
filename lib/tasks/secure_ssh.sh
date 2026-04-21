# >>> pi-task
# id: secure_ssh
# version: 1.2.0
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
  version=1.2.0 \
  default_enabled=0 \
  flags="--secure-ssh" \
  gate_var=SECURE_SSH

# Detect the SSH listen port from sshd_config; fall back to 22. Kept
# identical to ufw_firewall's helper so both tasks agree on the port.
_secure_ssh_port() {
  local port=""
  if [[ -r /etc/ssh/sshd_config ]]; then
    port=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
  fi
  echo "${port:-22}"
}

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

  local ssh_port
  ssh_port=$(_secure_ssh_port)

  # Stage fail2ban first so brute-force protection is live before sshd
  # reloads. Track the configured SSH port (not the literal "ssh"
  # service name) so a custom Port directive still gets jailed.
  ensure_packages fail2ban
  local jail_dir=/etc/fail2ban/jail.d
  local jail_file=$jail_dir/pi-optimiser-ssh.conf
  mkdir -p "$jail_dir"
  record_created "$jail_file"
  cat <<JAIL > "$jail_file"
[sshd]
enabled  = true
port     = ${ssh_port}
maxretry = 5
findtime = 600
bantime  = 600
backend  = systemd
JAIL
  log_info "Configured fail2ban jail for sshd on port ${ssh_port}"

  if unit_exists fail2ban.service; then
    systemctl enable --now fail2ban >/dev/null 2>&1 || log_warn "Unable to enable fail2ban service"
    # Restart so the freshly-written jail file is picked up even if
    # the daemon was already running before this task.
    systemctl restart fail2ban >/dev/null 2>&1 || true
  else
    log_warn "fail2ban.service not found after install; jail not active"
  fi

  # Write hardening directives to a drop-in that sorts LAST, so cloud-init
  # or distro-supplied fragments under sshd_config.d/ don't override us.
  # The main sshd_config ships with `Include /etc/ssh/sshd_config.d/*.conf`
  # on Debian 12+ / Raspberry Pi OS Bookworm and Ubuntu 22.04+; we verify
  # that Include directive is present before relying on the drop-in.
  local dropin_dir=/etc/ssh/sshd_config.d
  local dropin=$dropin_dir/99-pi-optimiser-hardening.conf
  local staging
  staging=$(mktemp)
  # Clean up all staged tempfiles on any return path — Ctrl-C, Python
  # exception, or early-exit on validation failure. Explicit `rm -f`
  # calls below are kept on the happy path; RETURN catches the rest.
  # main_stage is only populated in the main-file fallback branch and
  # is a no-op here until set.
  local main_stage=""
  # shellcheck disable=SC2064
  trap "rm -f '$staging' \"\${combined:-}\" \"\${main_stage:-}\"" RETURN
  chmod 600 "$staging"
  cat <<'DROPIN' > "$staging"
# Managed by pi-optimiser secure_ssh; do not edit by hand.
# Password auth is kept enabled by design — this task never
# disables it to avoid locking out users without SSH keys.
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
DROPIN

  # Safety gate: validate the new fragment against the LIVE sshd_config
  # by combining them into a temporary config and running sshd -t. If
  # validation fails, the real file is never touched.
  local combined
  combined=$(mktemp)
  chmod 600 "$combined"
  # sshd -t needs a single file. We read the live sshd_config, strip any
  # Include line pointing at our own drop-in (so we don't double-apply),
  # then append the staged drop-in. This mirrors the final on-disk view
  # sshd will see after we install the drop-in.
  cat "$ssh_config" > "$combined"
  printf '\n# --- pi-optimiser staged drop-in ---\n' >> "$combined"
  cat "$staging" >> "$combined"

  if ! sshd -t -f "$combined" >/dev/null 2>&1; then
    # Capture the real error for the operator.
    local err
    err=$(sshd -t -f "$combined" 2>&1 || true)
    log_error "sshd configuration validation FAILED against staged drop-in; refusing to install"
    log_error "sshd -t: ${err}"
    rm -f "$staging" "$combined"
    return 1
  fi
  rm -f "$combined"

  # Validation passed — install the drop-in atomically.
  mkdir -p "$dropin_dir"
  chmod 755 "$dropin_dir"
  record_created "$dropin"
  mv "$staging" "$dropin"
  chmod 644 "$dropin"
  chown root:root "$dropin" 2>/dev/null || true

  # Final paranoia check against the real file tree.
  if ! sshd -t >/dev/null 2>&1; then
    log_error "sshd -t failed AFTER installing drop-in; investigate $dropin"
    return 1
  fi

  # Verify the distro's main sshd_config actually pulls in drop-ins. If
  # not (old OpenSSH, custom build, or removed Include), fall back to
  # editing the main file directly — still staged and validated first.
  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$ssh_config"; then
    log_warn "sshd_config has no Include for sshd_config.d; applying hardening directly to $ssh_config"
    backup_file "$ssh_config"
    # Stage a copy, edit it, validate, then atomically replace.
    local main_stage
    main_stage=$(mktemp)
    chmod 600 "$main_stage"
    cp "$ssh_config" "$main_stage"
    SSHD_STAGE="$main_stage" update_sshd_config_option "PermitRootLogin" "no" "$main_stage"
    SSHD_STAGE="$main_stage" update_sshd_config_option "PasswordAuthentication" "yes" "$main_stage"
    SSHD_STAGE="$main_stage" update_sshd_config_option "KbdInteractiveAuthentication" "no" "$main_stage"
    SSHD_STAGE="$main_stage" update_sshd_config_option "ChallengeResponseAuthentication" "no" "$main_stage"
    SSHD_STAGE="$main_stage" update_sshd_config_option "UsePAM" "yes" "$main_stage"
    if ! sshd -t -f "$main_stage" >/dev/null 2>&1; then
      local err
      err=$(sshd -t -f "$main_stage" 2>&1 || true)
      log_error "sshd -t failed on staged main sshd_config; refusing to replace it"
      log_error "sshd -t: ${err}"
      rm -f "$main_stage"
      return 1
    fi
    mv "$main_stage" "$ssh_config"
    chmod 644 "$ssh_config"
    chown root:root "$ssh_config" 2>/dev/null || true
    if ! sshd -t >/dev/null 2>&1; then
      log_error "sshd -t failed AFTER replacing $ssh_config; investigate immediately"
      return 1
    fi
  fi

  # Reload (not restart) so the live control socket survives and any
  # active SSH session is preserved. Fall back to restart only if reload
  # is unsupported on this init.
  if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
    systemctl reload ssh >/dev/null 2>&1 \
      || systemctl restart ssh >/dev/null 2>&1 \
      || log_warn "Unable to reload ssh service"
  elif systemctl list-unit-files sshd.service >/dev/null 2>&1; then
    systemctl reload sshd >/dev/null 2>&1 \
      || systemctl restart sshd >/dev/null 2>&1 \
      || log_warn "Unable to reload sshd service"
  fi

  write_json_field "$CONFIG_OPTIMISER_STATE" "security.ssh.permit_root" "no"
  write_json_field "$CONFIG_OPTIMISER_STATE" "security.ssh.fail2ban" "enabled"
  write_json_field "$CONFIG_OPTIMISER_STATE" "security.ssh.port" "$ssh_port"

  log_info "SSH hardened (drop-in) and fail2ban enabled on port ${ssh_port}"
}
