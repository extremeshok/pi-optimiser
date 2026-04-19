# >>> pi-task
# id: locale
# version: 1.1.0
# description: Set default system locale
# category: system
# default_enabled: 0
# power_sensitive: 0
# flags: --locale
# gate_var: REQUESTED_LOCALE
# <<< pi-task

pi_task_register locale \
  description="Set default system locale" \
  category=system \
  version=1.1.0 \
  default_enabled=0 \
  flags="--locale" \
  gate_var=REQUESTED_LOCALE

run_locale() {
  if [[ -z "$REQUESTED_LOCALE" ]]; then
    log_info "No locale requested; skipping locale configuration"
    pi_skip_reason "not requested"
    return 2
  fi
  ensure_packages locales-all
  if [[ -f /etc/default/locale ]]; then
    backup_file /etc/default/locale
  fi
  cat <<EOF > /etc/default/locale
LANG=$REQUESTED_LOCALE
LC_ALL=$REQUESTED_LOCALE
EOF
  if update-locale LANG="$REQUESTED_LOCALE" LC_ALL="$REQUESTED_LOCALE" >/dev/null 2>&1; then
    log_info "Configured system locale to $REQUESTED_LOCALE"
  else
    log_warn "update-locale reported issues while setting $REQUESTED_LOCALE"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "locale.lang" "$REQUESTED_LOCALE"
}
