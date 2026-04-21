# >>> pi-task
# id: tailscale
# version: 1.2.0
# description: Install the Tailscale VPN client
# category: network
# default_enabled: 0
# power_sensitive: 0
# flags: --install-tailscale
# gate_var: INSTALL_TAILSCALE
# <<< pi-task

pi_task_register tailscale \
  description="Install the Tailscale VPN client" \
  category=network \
  version=1.2.0 \
  default_enabled=0 \
  flags="--install-tailscale" \
  gate_var=INSTALL_TAILSCALE

run_tailscale() {
  if [[ ${INSTALL_TAILSCALE:-0} -eq 0 ]]; then
    log_info "Tailscale not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  # Fail fast offline: the install pulls the Tailscale signing key and
  # repo index over HTTPS before touching apt.
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Network unavailable; cannot download Tailscale signing key/packages"
    pi_skip_reason "network unavailable"
    return 2
  fi
  load_os_release
  ensure_packages ca-certificates curl gnupg
  local repo_id repo_suite key_dir list_dir key_url
  repo_id=$OS_ID
  if [[ $repo_id == "raspbian" || $repo_id == "debian" ]]; then
    repo_id="debian"
  elif [[ $repo_id == "ubuntu" || $repo_id == "pop" ]]; then
    repo_id="ubuntu"
  elif [[ -n $OS_ID_LIKE && $OS_ID_LIKE == *debian* ]]; then
    repo_id="debian"
  fi
  repo_suite=$OS_CODENAME
  key_dir=$(dirname "$TAILSCALE_KEY_FILE")
  list_dir=$(dirname "$TAILSCALE_LIST_FILE")
  mkdir -p "$key_dir" "$list_dir"
  # Record the keyfile + apt list BEFORE writing so `--undo tailscale`
  # removes both and the repo is fully detached from apt.
  record_created "$TAILSCALE_KEY_FILE"
  record_created "$TAILSCALE_LIST_FILE"
  key_url="https://pkgs.tailscale.com/stable/${repo_id}/${repo_suite}.noarmor.gpg"
  # Secure curl defaults for the Tailscale apt signing key: HTTPS-only,
  # bounded redirects/timeouts, TLS 1.2+, retry-with-backoff.
  local -a _curl_secure=(
    --fail --silent --show-error --location
    --proto '=https' --proto-redir '=https'
    --max-redirs 5
    --connect-timeout 15 --max-time 120
    --tlsv1.2
    --retry 3 --retry-delay 2 --retry-connrefused
  )
  if ! curl "${_curl_secure[@]}" "$key_url" | gpg --dearmor > "$TAILSCALE_KEY_FILE"; then
    if [[ $repo_suite != "bookworm" ]]; then
      local fallback_url="https://pkgs.tailscale.com/stable/${repo_id}/bookworm.noarmor.gpg"
      log_warn "Tailscale key for $repo_suite unavailable; falling back to bookworm"
      if curl "${_curl_secure[@]}" "$fallback_url" | gpg --dearmor > "$TAILSCALE_KEY_FILE"; then
        repo_suite=bookworm
      else
        log_error "Failed to download Tailscale signing key from $fallback_url"
        return 1
      fi
    else
      log_error "Failed to download Tailscale signing key from $key_url"
      return 1
    fi
  fi
  chmod 644 "$TAILSCALE_KEY_FILE"
  cat <<EOF > "$TAILSCALE_LIST_FILE"
deb [signed-by=$TAILSCALE_KEY_FILE] https://pkgs.tailscale.com/stable/${repo_id} $repo_suite main
EOF
  chmod 644 "$TAILSCALE_LIST_FILE"
  log_info "Configured Tailscale repository for $repo_id $repo_suite"
  # shellcheck disable=SC2034  # reset to force a fresh apt_update_once
  APT_UPDATED=0
  if ! apt_update_once; then
    log_warn "apt-get update encountered issues after adding Tailscale repo"
  fi
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y tailscale; then
    log_error "Failed to install tailscale package"
    return 1
  fi
  systemctl enable --now tailscale >/dev/null 2>&1 || log_warn "Unable to enable tailscale service"
  if command -v tailscale >/dev/null 2>&1; then
    if tailscale set --accept-routes=true >/dev/null 2>&1; then
      log_info "Enabled accept-routes on Tailscale client"
    else
      log_warn "tailscale set --accept-routes=true failed (device may not be logged in yet)"
    fi
  fi
}
