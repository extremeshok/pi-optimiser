# >>> pi-task
# id: journald
# version: 1.1.1
# description: Keep systemd journal in RAM to reduce disk writes
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register journald \
  description="Keep systemd journal in RAM to reduce disk writes" \
  category=storage \
  version=1.1.1 \
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
}
