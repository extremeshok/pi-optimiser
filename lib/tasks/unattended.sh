# >>> pi-task
# id: unattended
# version: 1.1.1
# description: Auto-install security updates every 6 hours
# category: system
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register unattended \
  description="Auto-install security updates every 6 hours" \
  category=system \
  version=1.1.1 \
  default_enabled=1

run_unattended() {
  load_os_release
  ensure_packages unattended-upgrades
  local os_origin=${OS_ID^}
  local codename=$OS_CODENAME
  local uu_bin
  uu_bin=$(command -v unattended-upgrade || true)
  if [[ -z "$uu_bin" ]]; then
    if [[ -x /usr/bin/unattended-upgrade ]]; then
      uu_bin=/usr/bin/unattended-upgrade
    elif [[ -x /usr/sbin/unattended-upgrade ]]; then
      uu_bin=/usr/sbin/unattended-upgrade
    else
      log_warn "unattended-upgrade binary not found; skipping timer setup"
      pi_skip_reason "unattended-upgrade binary missing"
      return 2
    fi
  fi
  # record_created is edit-safe: if the file already exists it falls
  # back to backup_file, so --undo restores the prior content instead
  # of deleting it.
  record_created "$UNATTENDED_CONF_FILE"
  record_created "$UNATTENDED_SERVICE"
  record_created "$UNATTENDED_TIMER"
  cat <<CFG > "$UNATTENDED_CONF_FILE"
Unattended-Upgrade::Origins-Pattern {
        "origin=${os_origin},codename=${codename}-security";
        "origin=Debian,codename=${codename}-security";
        "origin=Raspberry Pi Foundation,codename=${codename}";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
CFG
  # Hardening rationale:
  #   - unattended-upgrade needs /var/lib/dpkg, /var/cache/apt,
  #     /var/log/unattended-upgrades and must invoke dpkg/apt hooks, so
  #     ProtectSystem=strict would break installs. Leave unset and rely
  #     on the milder directives below which don't block package ops.
  #   - ProtectHome=true — package upgrades never touch user homes.
  #   - NoNewPrivileges: intentionally NOT set — dpkg triggers may call
  #     helpers that legitimately need setuid (e.g. /usr/bin/sudo postinst
  #     chmod 4755). Forcing it would break some postinst scripts.
  cat <<CFG > "$UNATTENDED_SERVICE"
[Unit]
Description=Run unattended-upgrades (pi-optimiser)
Documentation=man:unattended-upgrade(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${uu_bin} --quiet
SuccessExitStatus=0 2
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
CFG
  # RandomizedDelaySec=30min prevents a thundering-herd against the
  # Debian/Raspbian mirrors when many Pis boot simultaneously (e.g. a
  # fleet coming back online after a site-wide power event).
  cat <<'CFG' > "$UNATTENDED_TIMER"
[Unit]
Description=Run unattended-upgrades every 6 hours (pi-optimiser)
Documentation=man:unattended-upgrade(8)

[Timer]
OnBootSec=20min
OnUnitActiveSec=6h
RandomizedDelaySec=30min
AccuracySec=5min
Persistent=true

[Install]
WantedBy=timers.target
CFG
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now pi-unattended-upgrades.timer >/dev/null 2>&1 || log_warn "Could not enable pi-unattended-upgrades.timer"
}
