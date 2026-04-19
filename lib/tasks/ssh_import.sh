# >>> pi-task
# id: ssh_import
# version: 1.1.0
# description: Import SSH authorized_keys from GitHub or an HTTPS URL
# category: security
# default_enabled: 0
# power_sensitive: 0
# flags: --ssh-import-github,--ssh-import-url
# gate_var: SSH_IMPORT_GITHUB
# <<< pi-task

pi_task_register ssh_import \
  description="Import SSH authorized_keys from GitHub or an HTTPS URL" \
  category=security \
  version=1.1.0 \
  default_enabled=0 \
  flags="--ssh-import-github,--ssh-import-url" \
  gate_var=SSH_IMPORT_GITHUB

run_ssh_import() {
  if [[ -z "$SSH_IMPORT_GITHUB" && -z "$SSH_IMPORT_URL" ]]; then
    log_info "No SSH key import requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  ensure_packages curl ca-certificates
  local target_user=${SUDO_USER:-}
  if [[ -z "$target_user" || "$target_user" == "root" ]]; then
    target_user=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
  fi
  if [[ -z "$target_user" ]]; then
    log_warn "Unable to determine target user for SSH key import"
    pi_skip_reason "no target user"
    return 2
  fi
  local home_dir
  home_dir=$(getent passwd "$target_user" | cut -d: -f6)
  if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
    log_warn "Home directory for $target_user not found"
    pi_skip_reason "home missing"
    return 2
  fi
  local ssh_dir="$home_dir/.ssh"
  local authorized="$ssh_dir/authorized_keys"
  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  touch "$authorized"
  chmod 600 "$authorized"
  chown -R "$target_user:$target_user" "$ssh_dir"

  local tmp_keys
  tmp_keys=$(mktemp)
  local imported=0

  # Append keys from a downloaded file into authorized_keys, de-duping
  # by the key comment (fingerprint would be better but requires parsing
  # each line; the comment is a close-enough proxy for our purposes).
  _ssh_import_merge_keys() {
    local keys_file=$1 auth_file=$2 src_label=$3
    KEYS_FILE="$keys_file" AUTH_FILE="$auth_file" SRC="$src_label" run_python <<'PY'
import os
from pathlib import Path
keys = Path(os.environ['KEYS_FILE']).read_text().splitlines()
auth = Path(os.environ['AUTH_FILE'])
existing = set()
if auth.exists():
    for line in auth.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            parts = stripped.split()
            existing.add(parts[-1] if len(parts) >= 3 else stripped)
added = []
for key in keys:
    key = key.strip()
    if not key or key.startswith('#'):
        continue
    parts = key.split()
    marker = parts[-1] if len(parts) >= 3 else key
    if marker in existing:
        continue
    added.append(key)
    existing.add(marker)
if added:
    with auth.open('a') as fh:
        fh.write(f"\n# pi-optimiser import: {os.environ['SRC']}\n")
        for k in added:
            fh.write(k + "\n")
print(len(added))
PY
  }

  if [[ -n "$SSH_IMPORT_GITHUB" ]]; then
    if ! validate_github_handle "$SSH_IMPORT_GITHUB"; then
      log_error "--ssh-import-github: '$SSH_IMPORT_GITHUB' is not a valid GitHub handle"
      rm -f "$tmp_keys"
      return 1
    fi
    local gh_url="https://github.com/${SSH_IMPORT_GITHUB}.keys"
    if curl -fsSL "$gh_url" -o "$tmp_keys" && [[ -s "$tmp_keys" ]]; then
      _ssh_import_merge_keys "$tmp_keys" "$authorized" "github:$SSH_IMPORT_GITHUB" >/dev/null
      imported=1
      log_info "Imported SSH keys from $gh_url into $authorized"
    else
      log_warn "Failed to fetch GitHub keys from $gh_url"
    fi
  fi

  if [[ -n "$SSH_IMPORT_URL" ]]; then
    if [[ $SSH_IMPORT_URL != https://* ]]; then
      log_error "--ssh-import-url must use https://"
      rm -f "$tmp_keys"
      return 1
    fi
    if curl -fsSL "$SSH_IMPORT_URL" -o "$tmp_keys" && [[ -s "$tmp_keys" ]]; then
      _ssh_import_merge_keys "$tmp_keys" "$authorized" "url:$SSH_IMPORT_URL" >/dev/null
      imported=1
      log_info "Imported SSH keys from $SSH_IMPORT_URL into $authorized"
    else
      log_warn "Failed to fetch keys from $SSH_IMPORT_URL"
    fi
  fi

  rm -f "$tmp_keys"
  chown "$target_user:$target_user" "$authorized"
  chmod 600 "$authorized"

  if [[ $imported -eq 0 ]]; then
    pi_skip_reason "no keys imported"
    return 2
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "ssh.keys_imported_for" "$target_user"
}
