# ======================================================================
# lib/util/update.sh — self-update against the GitHub repo
#
# Functions: pi_check_update, pi_self_update,
#            pi_enable_update_timer, pi_disable_update_timer,
#            pi_update_verify_signature
#
# Update model (v1): download the tarball at the configured ref, stage
# a new release dir alongside the current one, verify it parses, then
# flip /opt/pi-optimiser/current via an atomic rename. Keeps N=2 old
# releases for --rollback.
#
# Ref resolution (environment or built-in default):
#   PI_OPTIMISER_REF   — branch/tag/commit to track (default: master)
#   PI_OPTIMISER_REPO  — owner/name on github.com (default: extremeshok/pi-optimiser)
#
# Integrity posture: TLS from GitHub + optional minisign verification
# (--require-signature). No implicit update path runs without an
# explicit --update or the opt-in timer.
# ======================================================================

PI_OPTIMISER_REPO_DEFAULT="extremeshok/pi-optimiser"
PI_OPTIMISER_REF_DEFAULT="master"
PI_UPDATE_TIMER_UNIT="pi-optimiser-update.timer"
PI_UPDATE_SERVICE_UNIT="pi-optimiser-update.service"
PI_UPDATE_SIG_PUBKEY="${PI_OPTIMISER_PUBKEY:-/etc/pi-optimiser/trusted.pub}"

# Resolve the commit SHA at the configured ref via the GitHub API.
# Prints the 40-char hash on stdout. Returns non-zero on any failure.
pi_update_remote_sha() {
  local repo=${PI_OPTIMISER_REPO:-$PI_OPTIMISER_REPO_DEFAULT}
  local ref=${PI_OPTIMISER_REF:-$PI_OPTIMISER_REF_DEFAULT}
  local url="https://api.github.com/repos/${repo}/commits/${ref}"
  local body
  body=$(mktemp)
  if ! curl -fsSL -H 'Accept: application/vnd.github+json' "$url" -o "$body" 2>/dev/null; then
    rm -f "$body"
    return 1
  fi
  local sha
  sha=$(GH_BODY="$body" run_python <<'PY' || echo ""
import json, os, sys
try:
    with open(os.environ["GH_BODY"]) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(1)
v = data.get("sha")
if not v:
    sys.exit(1)
print(v)
PY
  )
  rm -f "$body"
  if [[ -z "$sha" ]]; then
    return 1
  fi
  echo "$sha"
}

# Last-installed commit SHA, from state (CONFIG_OPTIMISER_STATE).
pi_update_installed_sha() {
  read_json_field "$CONFIG_OPTIMISER_STATE" "update.commit_sha" 2>/dev/null || echo ""
}

# --check-update: show whether a newer commit exists on the remote ref.
pi_check_update() {
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_error "Network unavailable; cannot check for updates"
    return 1
  fi
  local remote installed
  remote=$(pi_update_remote_sha) || {
    log_error "Failed to resolve remote commit SHA"
    return 1
  }
  installed=$(pi_update_installed_sha)
  local ref=${PI_OPTIMISER_REF:-$PI_OPTIMISER_REF_DEFAULT}
  if [[ ${PI_OUTPUT_JSON:-0} -eq 1 ]]; then
    PI_REMOTE="$remote" PI_INSTALLED="$installed" PI_REF="$ref" run_python <<'PY'
import json, os, sys
out = {
    "ref": os.environ["PI_REF"],
    "remote_sha": os.environ["PI_REMOTE"],
    "installed_sha": os.environ["PI_INSTALLED"] or None,
    "update_available": os.environ["PI_REMOTE"] != os.environ["PI_INSTALLED"],
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
    return 0
  fi
  echo "Ref:           $ref"
  echo "Remote SHA:    $remote"
  echo "Installed SHA: ${installed:-<unknown>}"
  if [[ -z "$installed" || "$installed" != "$remote" ]]; then
    echo "Status:        UPDATE AVAILABLE"
    return 0
  fi
  echo "Status:        up to date"
}

# --update: stage + swap + flip launcher.
pi_self_update() {
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_error "Network unavailable; cannot self-update"
    return 1
  fi
  local repo=${PI_OPTIMISER_REPO:-$PI_OPTIMISER_REPO_DEFAULT}
  local ref=${PI_OPTIMISER_REF:-$PI_OPTIMISER_REF_DEFAULT}
  local remote installed
  remote=$(pi_update_remote_sha) || { log_error "Failed to resolve remote SHA"; return 1; }
  installed=$(pi_update_installed_sha)
  if [[ -n "$installed" && "$installed" == "$remote" && ${FORCE:-0} -eq 0 ]]; then
    log_info "Already on $remote (ref: $ref); nothing to do. Pass --force to reinstall."
    return 0
  fi

  log_info "Updating to $remote (ref: $ref)"

  local prefix="${PI_PREFIX:-/opt/pi-optimiser}"
  local staging="$prefix/.staging"
  local release_dir
  release_dir="$prefix/releases/update-$(date +%Y%m%d%H%M%S)-${remote:0:7}"
  rm -rf "$staging"
  mkdir -p "$staging" "$prefix/releases"

  local tar_url="https://codeload.github.com/${repo}/tar.gz/${remote}"
  local tar_path="$staging/source.tgz"
  if ! curl -fsSL "$tar_url" -o "$tar_path"; then
    log_error "Failed to download tarball $tar_url"
    return 1
  fi

  if ! tar -xzf "$tar_path" -C "$staging"; then
    log_error "Tarball extraction failed"
    return 1
  fi
  # GitHub's tar extracts under <repo>-<ref-or-sha>/
  local src_root
  src_root=$(find "$staging" -maxdepth 1 -mindepth 1 -type d | head -n1)
  if [[ -z "$src_root" ]]; then
    log_error "Unexpected tarball layout"
    return 1
  fi

  # Optional minisign verification (opt-in via --require-signature).
  if [[ ${PI_REQUIRE_SIGNATURE:-0} -eq 1 ]]; then
    if ! pi_update_verify_signature "$src_root"; then
      log_error "Signature verification failed; aborting update"
      return 1
    fi
  fi

  # Static syntax check on the new script before swapping.
  if ! bash -n "$src_root/pi-optimiser.sh"; then
    log_error "Staged pi-optimiser.sh fails bash -n; aborting update"
    return 1
  fi

  mkdir -p "$release_dir"
  local item
  for item in pi-optimiser.sh lib scripts install.sh README.md AGENTS.md LICENSE SECURITY.md; do
    [[ -e "$src_root/$item" ]] && cp -a "$src_root/$item" "$release_dir/"
  done
  chmod +x "$release_dir/pi-optimiser.sh" 2>/dev/null || true

  ln -sfn "$release_dir" "$prefix/current.new"
  mv -Tf "$prefix/current.new" "$prefix/current"

  local launcher=${PI_OPTIMISER_BIN:-/usr/local/sbin/pi-optimiser}
  mkdir -p "$(dirname "$launcher")"
  ln -sf "$prefix/current/pi-optimiser.sh" "$launcher"

  # Retain only the 2 most recent releases to keep SD space free.
  local releases_root="$prefix/releases"
  mapfile -t releases < <(ls -1t "$releases_root" 2>/dev/null)
  local keep=${PI_OPTIMISER_KEEP:-2}
  if (( ${#releases[@]} > keep )); then
    local stale
    for stale in "${releases[@]:$keep}"; do
      [[ -z "$stale" ]] && continue
      rm -rf "${releases_root:?}/${stale:?}"
    done
  fi

  rm -rf "$staging"

  write_json_field "$CONFIG_OPTIMISER_STATE" "update.commit_sha" "$remote"
  write_json_field "$CONFIG_OPTIMISER_STATE" "update.applied_at" \
    "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
  write_json_field "$CONFIG_OPTIMISER_STATE" "update.ref" "$ref"
  log_info "Update complete → $release_dir"
  log_info "Next run from the launcher will pick up the new release."
}

# Minisign signature verification stub. Real signing infrastructure is
# deferred; this function is wired but no-ops when the public key is
# absent. Callers gate on --require-signature, which bails hard if this
# returns non-zero.
pi_update_verify_signature() {
  local src_root=$1
  local sig_file="$src_root/pi-optimiser.sh.minisig"
  if [[ ! -f "$sig_file" ]]; then
    log_warn "--require-signature: no pi-optimiser.sh.minisig in release tarball"
    return 1
  fi
  if [[ ! -f "$PI_UPDATE_SIG_PUBKEY" ]]; then
    log_warn "--require-signature: public key not found at $PI_UPDATE_SIG_PUBKEY"
    return 1
  fi
  if ! command -v minisign >/dev/null 2>&1; then
    log_warn "--require-signature: minisign binary not installed"
    return 1
  fi
  if minisign -V -p "$PI_UPDATE_SIG_PUBKEY" -m "$src_root/pi-optimiser.sh" >/dev/null 2>&1; then
    log_info "Signature verified against $PI_UPDATE_SIG_PUBKEY"
    return 0
  fi
  return 1
}

# Install a systemd timer that runs `pi-optimiser --update --yes` on a
# daily cadence with randomized delay.
pi_enable_update_timer() {
  local launcher=${PI_OPTIMISER_BIN:-/usr/local/sbin/pi-optimiser}
  if [[ ! -x "$launcher" && ! -L "$launcher" ]]; then
    log_error "Launcher $launcher missing; run the installer first"
    return 1
  fi
  mkdir -p /etc/systemd/system
  cat <<CFG > "/etc/systemd/system/$PI_UPDATE_SERVICE_UNIT"
[Unit]
Description=pi-optimiser self-update (opt-in)
Documentation=https://github.com/extremeshok/pi-optimiser
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$launcher --update --yes --no-tui
SuccessExitStatus=0
CFG
  cat <<'CFG' > "/etc/systemd/system/pi-optimiser-update.timer"
[Unit]
Description=pi-optimiser self-update timer (opt-in)
Documentation=https://github.com/extremeshok/pi-optimiser

[Timer]
OnBootSec=30min
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
CFG
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now "$PI_UPDATE_TIMER_UNIT" >/dev/null 2>&1 \
    || { log_error "Failed to enable $PI_UPDATE_TIMER_UNIT"; return 1; }
  log_info "Update timer enabled: $PI_UPDATE_TIMER_UNIT (daily + up to 6h jitter)"
}

pi_disable_update_timer() {
  if unit_exists "$PI_UPDATE_TIMER_UNIT"; then
    systemctl disable --now "$PI_UPDATE_TIMER_UNIT" >/dev/null 2>&1 || true
  fi
  rm -f "/etc/systemd/system/$PI_UPDATE_TIMER_UNIT" \
        "/etc/systemd/system/$PI_UPDATE_SERVICE_UNIT"
  systemctl daemon-reload >/dev/null 2>&1 || true
  log_info "Update timer disabled"
}
