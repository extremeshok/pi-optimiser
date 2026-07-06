# >>> pi-task
# id: sudo_policy
# version: 1.0.0
# description: Reconcile Raspberry Pi sudo password policy
# category: security
# default_enabled: 0
# power_sensitive: 0
# flags: --sudo-password-required,--sudo-passwordless
# gate_var: SUDO_POLICY_SET
# <<< pi-task

pi_task_register sudo_policy \
  description="Reconcile Raspberry Pi sudo password policy" \
  category=security \
  version=1.0.0 \
  default_enabled=0 \
  flags="--sudo-password-required,--sudo-passwordless" \
  gate_var=SUDO_POLICY_SET

_sudo_policy_mode() {
  if [[ ${SUDO_POLICY_PASSWORDLESS:-0} -eq 1 ]]; then
    printf '%s\n' "passwordless"
  else
    printf '%s\n' "password-required"
  fi
}

_sudo_policy_validate() {
  if command -v visudo >/dev/null 2>&1; then
    visudo -c >/dev/null 2>&1
    return
  fi
  log_warn "visudo not available; sudoers syntax was not validated"
  return 0
}

_sudo_policy_strip_nopasswd() {
  local file=$1
  [[ -f "$file" ]] || return 0
  if ! grep -q 'NOPASSWD' "$file" 2>/dev/null; then
    return 0
  fi
  backup_file "$file"
  SUDOERS_FILE="$file" run_python <<'PY'
import os
from pathlib import Path
path = Path(os.environ["SUDOERS_FILE"])
text = path.read_text()
text = text.replace("NOPASSWD:", "")
path.write_text(text)
PY
  chmod 0440 "$file" 2>/dev/null || true
}

_sudo_policy_warn_leftovers() {
  local leftovers
  leftovers=$(
    grep -RIl 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null \
      | grep -v '\.pi-optimiser\.' \
      | tr '\n' ' ' || true
  )
  if [[ -n "$leftovers" ]]; then
    log_warn "Other sudoers files still contain NOPASSWD: $leftovers"
  fi
}

run_sudo_policy() {
  if [[ ${SUDO_POLICY_SET:-0} -eq 0 ]]; then
    log_info "Sudo password policy not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi

  local mode
  mode=$(_sudo_policy_mode)
  local primary="/etc/sudoers.d/010_pi-nopasswd"
  local cloud_users="/etc/sudoers.d/90-cloud-init-users"

  case $mode in
    password-required)
      if [[ -e "$primary" || -L "$primary" ]]; then
        backup_file "$primary"
        rm -f "$primary"
        log_info "Removed $primary so sudo requires the user's password"
      else
        log_info "$primary is already absent"
      fi
      _sudo_policy_strip_nopasswd "$cloud_users"
      if ! _sudo_policy_validate; then
        log_error "sudoers validation failed after password-required policy"
        return 1
      fi
      _sudo_policy_warn_leftovers
      if [[ ! -f /etc/cloud/cloud-init.disabled && -f "$cloud_users" ]]; then
        log_warn "cloud-init can recreate sudo policy on boot; consider --cloud-init-finalize after provisioning"
      fi
      write_json_field "$CONFIG_OPTIMISER_STATE" "security.sudo_policy" "password-required"
      ;;
    passwordless)
      if ! command -v visudo >/dev/null 2>&1; then
        log_error "visudo is required before writing passwordless sudo policy"
        return 1
      fi
      mkdir -p /etc/sudoers.d
      local tmp
      tmp=$(mktemp)
      # shellcheck disable=SC2064
      trap "rm -f '$tmp'" RETURN
      printf '%%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n' > "$tmp"
      chmod 0440 "$tmp"
      if ! visudo -cf "$tmp" >/dev/null 2>&1; then
        log_error "Generated sudoers policy did not validate"
        return 1
      fi
      record_created "$primary"
      install -o root -g root -m 0440 "$tmp" "$primary"
      if ! _sudo_policy_validate; then
        log_error "sudoers validation failed after passwordless policy"
        return 1
      fi
      log_info "Passwordless sudo enabled for members of the sudo group"
      write_json_field "$CONFIG_OPTIMISER_STATE" "security.sudo_policy" "passwordless"
      ;;
    *)
      log_error "Internal error: unsupported sudo policy '$mode'"
      return 1
      ;;
  esac
}
