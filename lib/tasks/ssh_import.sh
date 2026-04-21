# >>> pi-task
# id: ssh_import
# version: 1.2.0
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
  version=1.2.0 \
  default_enabled=0 \
  flags="--ssh-import-github,--ssh-import-url" \
  gate_var=SSH_IMPORT_GITHUB

run_ssh_import() {
  if [[ -z "$SSH_IMPORT_GITHUB" && -z "$SSH_IMPORT_URL" ]]; then
    log_info "No SSH key import requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  # The import pulls keys over HTTPS — bail early rather than truncating
  # authorized_keys with a half-downloaded response.
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Network unavailable; cannot fetch SSH keys from GitHub/URL"
    pi_skip_reason "network unavailable"
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
  # Clean up on any return path (including Ctrl-C mid-download) so a
  # curl aborted mid-flight doesn't leave /tmp/tmp.XXXXX behind with
  # partial key material. Explicit `rm -f "$tmp_keys"` calls on the
  # happy paths below are kept; RETURN catches the error paths too.
  # shellcheck disable=SC2064
  trap "rm -f '$tmp_keys'" RETURN
  local imported=0
  # Secure curl defaults for key imports: HTTPS-only (we already reject
  # non-https for --ssh-import-url above), bounded redirects + timeouts
  # to avoid hung downloads, TLS 1.2+, retry-with-backoff on transient
  # network errors. -f ensures a non-2xx response does not leave a
  # partially-written HTML error page in $tmp_keys.
  local -a _curl_secure=(
    --fail --silent --show-error --location
    --proto '=https' --proto-redir '=https'
    --max-redirs 5
    --connect-timeout 15 --max-time 60
    --tlsv1.2
    --retry 3 --retry-delay 2 --retry-connrefused
  )

  # Cap on downloaded key file size (128 KiB). A legitimate GitHub .keys
  # response is a few KiB at most; anything larger is either a mistake
  # or an attempt to wedge the box.
  local _max_keys_bytes=131072

  # Allowlist of acceptable key types. Rejects ssh-dss (DSA, deprecated),
  # ssh-rsa1 (SSH-1 RSA), and anything we don't recognise. This is the
  # modern OpenSSH set.
  local _allowed_key_types='ssh-ed25519,ssh-rsa,ssh-ecdsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com'

  # Append keys from a downloaded file into authorized_keys. We:
  #   1. Reject the whole import if any line isn't a well-formed public
  #      key of an allowlisted type — a single bogus line means the
  #      source is compromised or misconfigured.
  #   2. De-dupe against existing lines by key comment (fingerprint
  #      would be stronger but requires parsing; good-enough for our
  #      target-user import flow).
  _ssh_import_merge_keys() {
    local keys_file=$1 auth_file=$2 src_label=$3
    KEYS_FILE="$keys_file" AUTH_FILE="$auth_file" SRC="$src_label" \
    ALLOWED_TYPES="$_allowed_key_types" run_python <<'PY'
import base64
import os
import sys
from pathlib import Path

allowed = {t.strip() for t in os.environ['ALLOWED_TYPES'].split(',') if t.strip()}
keys_path = Path(os.environ['KEYS_FILE'])
auth = Path(os.environ['AUTH_FILE'])

raw = keys_path.read_text()
lines = raw.splitlines()

# A legitimate .keys listing has at most a few dozen entries; cap to
# stop a hostile source from filling authorized_keys with garbage.
MAX_KEYS = 50
# Individual key lines should be well under 16 KiB. ssh-rsa 16384 is
# ~3 KiB base64; this is generous.
MAX_LINE = 16384

candidates = []
for lineno, raw_line in enumerate(lines, start=1):
    line = raw_line.strip()
    if not line or line.startswith('#'):
        continue
    if len(raw_line) > MAX_LINE:
        print(f"reject: line {lineno} exceeds {MAX_LINE} bytes", file=sys.stderr)
        sys.exit(2)
    parts = line.split()
    # A valid public key line is "<type> <base64-blob> [comment...]"
    # OpenSSH also accepts leading option lists ("from=..., no-pty ssh-...").
    # We reject option-lists — this importer only supports plain key lines.
    if len(parts) < 2:
        print(f"reject: line {lineno} does not look like a public key", file=sys.stderr)
        sys.exit(2)
    key_type = parts[0]
    if key_type not in allowed:
        print(f"reject: line {lineno} uses disallowed key type '{key_type}'", file=sys.stderr)
        sys.exit(2)
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except Exception:
        print(f"reject: line {lineno} has non-base64 key material", file=sys.stderr)
        sys.exit(2)
    if len(blob) < 32 or len(blob) > 8192:
        print(f"reject: line {lineno} key material has suspicious size ({len(blob)} bytes)", file=sys.stderr)
        sys.exit(2)
    # The blob's first 4-byte length-prefixed string must match the
    # declared key type (OpenSSH SSH2 wire format). This catches
    # type-vs-blob mismatches (e.g. tampered exports).
    if len(blob) >= 4:
        name_len = int.from_bytes(blob[:4], 'big')
        if name_len <= 0 or name_len > 128 or 4 + name_len > len(blob):
            print(f"reject: line {lineno} malformed blob prefix", file=sys.stderr)
            sys.exit(2)
        declared = blob[4:4 + name_len].decode('ascii', errors='replace')
        # ssh-ed25519 blob names itself "ssh-ed25519"; ecdsa-sha2-nistp256
        # names itself "ecdsa-sha2-nistp256"; sk-* variants embed the
        # type as-is too. Accept exact match or ecdsa prefix relationship.
        if declared != key_type and not (
            key_type.startswith('ecdsa') and declared.startswith('ecdsa')
        ) and not (
            key_type.startswith('sk-') and declared == key_type.split('@', 1)[0]
        ):
            print(f"reject: line {lineno} declares '{key_type}' but blob names '{declared}'", file=sys.stderr)
            sys.exit(2)
    candidates.append(line)

if len(candidates) > MAX_KEYS:
    print(f"reject: {len(candidates)} keys exceeds maximum of {MAX_KEYS}", file=sys.stderr)
    sys.exit(2)

existing = set()
if auth.exists():
    for line in auth.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            parts = stripped.split()
            existing.add(parts[-1] if len(parts) >= 3 else stripped)

added = []
for key in candidates:
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
    if curl "${_curl_secure[@]}" --max-filesize "$_max_keys_bytes" "$gh_url" -o "$tmp_keys" \
       && [[ -s "$tmp_keys" ]]; then
      if _ssh_import_merge_keys "$tmp_keys" "$authorized" "github:$SSH_IMPORT_GITHUB" >/dev/null; then
        imported=1
        log_info "Imported SSH keys from $gh_url into $authorized"
      else
        log_warn "Rejected GitHub keys from $gh_url (validation failed; nothing written)"
      fi
    else
      log_warn "Failed to fetch GitHub keys from $gh_url"
    fi
  fi

  if [[ -n "$SSH_IMPORT_URL" ]]; then
    # Defense in depth: the CLI parser runs validate_https_url on --ssh-import-url,
    # but the YAML/TUI paths may also populate SSH_IMPORT_URL. Re-check here so
    # a crafted config file can't smuggle whitespace, control chars, shell
    # metacharacters, or user:pass@host credentials past the final curl.
    if ! validate_https_url "$SSH_IMPORT_URL"; then
      log_error "--ssh-import-url: URL failed strict https validation"
      rm -f "$tmp_keys"
      return 1
    fi
    if curl "${_curl_secure[@]}" --max-filesize "$_max_keys_bytes" "$SSH_IMPORT_URL" -o "$tmp_keys" \
       && [[ -s "$tmp_keys" ]]; then
      if _ssh_import_merge_keys "$tmp_keys" "$authorized" "url:$SSH_IMPORT_URL" >/dev/null; then
        imported=1
        log_info "Imported SSH keys from $SSH_IMPORT_URL into $authorized"
      else
        log_warn "Rejected keys from $SSH_IMPORT_URL (validation failed; nothing written)"
      fi
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
