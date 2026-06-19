# >>> pi-task
# id: omniban
# version: 1.0.0
# description: Install omniban, the unified firewall/IDS ban manager
# category: security
# default_enabled: 0
# power_sensitive: 0
# flags: --install-omniban
# gate_var: INSTALL_OMNIBAN
# <<< pi-task

pi_task_register omniban \
  description="Install omniban, the unified firewall/IDS ban manager" \
  category=security \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-omniban" \
  gate_var=INSTALL_OMNIBAN

# omniban (https://github.com/extremeshok/omniban) is a single static Go
# binary that centralises IP-ban management across fail2ban, CrowdSec,
# sshguard, UFW, firewalld, Shorewall, nftables, iptables, ipset and a
# dozen other backends. It ships no daemon and needs no config — it
# auto-detects whichever security tools are already installed and routes
# ban/unban commands back through the owning backend.
#
# The manifest runs this AFTER secure_ssh (fail2ban) and ufw_firewall so
# those backends already exist for omniban to detect on first run.
#
# Upstream publishes a static binary per release; the documented install
# path is scripts/install.sh, which detects the CPU architecture
# (amd64/arm64), downloads the matching binary from the GitHub release,
# and drops it at /usr/local/bin/omniban. We fetch that installer over a
# hardened TLS channel (pi_curl_secure) to a temp file and run it from
# disk, rather than the blind `curl | bash` the upstream README suggests,
# so the download honours pi-optimiser's pinned TLS/redirect policy and
# the script is auditable before it executes.
#
# Upstream publishes no git tags yet, so the installer tracks the default
# branch. A security-conscious operator can pin to a tag or commit SHA
# once one exists by exporting OMNIBAN_INSTALL_REF=<ref> (mirrors
# pi-optimiser's own PI_OPTIMISER_REF). The ref is validated with
# validate_git_ref before it is interpolated into the download URL.
OMNIBAN_INSTALL_REF="${OMNIBAN_INSTALL_REF:-master}"

run_omniban() {
  if [[ ${INSTALL_OMNIBAN:-0} -eq 0 ]]; then
    log_info "omniban not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  # Fail fast offline: the installer downloads the release binary over
  # HTTPS. Running it without a network would leave a half-state.
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Network unavailable; cannot download omniban"
    pi_skip_reason "network unavailable"
    return 2
  fi

  if ! validate_git_ref "$OMNIBAN_INSTALL_REF"; then
    log_error "omniban: invalid OMNIBAN_INSTALL_REF '$OMNIBAN_INSTALL_REF'"
    return 1
  fi
  local install_url="https://raw.githubusercontent.com/extremeshok/omniban/${OMNIBAN_INSTALL_REF}/scripts/install.sh"

  local omniban_bin=/usr/local/bin/omniban
  if command -v omniban >/dev/null 2>&1; then
    log_info "omniban already installed ($(command -v omniban)); re-running installer to refresh to latest"
  fi

  ensure_packages ca-certificates curl

  # Register the binary as created BEFORE the installer runs so
  # `--undo omniban` removes it even if a partial run dies mid-download.
  record_created "$omniban_bin"

  local tmp_installer
  tmp_installer=$(mktemp) || { log_error "omniban: mktemp failed"; return 1; }
  # shellcheck disable=SC2064  # expand tmp path now, not at trap-fire time
  trap "rm -f \"$tmp_installer\"" RETURN

  if ! pi_curl_secure "$install_url" -o "$tmp_installer"; then
    log_error "omniban: failed to download installer from $install_url"
    return 1
  fi
  if [[ ! -s "$tmp_installer" ]]; then
    log_error "omniban: downloaded installer is empty"
    return 1
  fi

  if ! bash "$tmp_installer"; then
    log_error "omniban: installer exited non-zero"
    return 1
  fi

  if command -v omniban >/dev/null 2>&1; then
    log_info "omniban installed at $(command -v omniban)"
    log_info "No configuration needed; run 'sudo omniban' for the TUI or 'omniban --help' for the CLI"
  else
    log_warn "omniban installer completed but the binary was not found on PATH"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "security.omniban" "installed"
}
