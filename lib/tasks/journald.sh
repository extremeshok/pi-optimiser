# >>> pi-task
# id: journald
# version: 1.2.0
# description: Keep systemd journal in RAM to reduce disk writes
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register journald \
  description="Keep systemd journal in RAM to reduce disk writes" \
  category=storage \
  version=1.2.0 \
  default_enabled=1

run_journald() {
  mkdir -p "$(dirname "$JOURNALD_CONF_FILE")"
  record_created "$JOURNALD_CONF_FILE"
  cat <<'CFG' > "$JOURNALD_CONF_FILE"
[Journal]
Storage=volatile
RuntimeMaxUse=50M
SystemMaxUse=50M
MaxRetentionSec=1week
CFG
  systemctl restart systemd-journald >/dev/null 2>&1 || log_warn "systemd-journald restart failed"
  # Storage=volatile keeps the journal in RAM to spare the SD card, but
  # that means logs do NOT survive a reboot. Make the tradeoff explicit
  # so an operator debugging a crash isn't surprised by an empty journal.
  log_info "Journal is volatile (RAM-only): logs are cleared on reboot. To keep persistent logs, skip the journald task or set Storage=persistent in $JOURNALD_CONF_FILE."
}
