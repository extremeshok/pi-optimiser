# >>> pi-task
# id: locale
# version: 1.2.0
# description: Set the default system locale
# category: system
# default_enabled: 0
# power_sensitive: 0
# flags: --locale
# gate_var: REQUESTED_LOCALE
# <<< pi-task

pi_task_register locale \
  description="Set the default system locale" \
  category=system \
  version=1.2.0 \
  default_enabled=0 \
  flags="--locale" \
  gate_var=REQUESTED_LOCALE

run_locale() {
  if [[ -z "$REQUESTED_LOCALE" ]]; then
    log_info "No locale requested; skipping locale configuration"
    pi_skip_reason "not requested"
    return 2
  fi
  # REQUESTED_LOCALE flows from CLI/config into /etc/default/locale,
  # which is sourced by /etc/profile on every login. Reject anything
  # that isn't a plain POSIX locale so a value like
  #   en_GB.UTF-8\nLD_PRELOAD=/tmp/evil.so
  # can't inject additional shell assignments into a file every
  # user's login shell evaluates.
  if ! validate_locale "$REQUESTED_LOCALE"; then
    log_error "Invalid locale '$REQUESTED_LOCALE' (expected ll_CC[.encoding][@modifier])"
    return 1
  fi
  ensure_packages locales-all
  # /etc/default/locale almost always exists, but handle the rare
  # case where it doesn't so --undo still does the right thing.
  record_created /etc/default/locale
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
