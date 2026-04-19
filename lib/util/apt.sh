# ======================================================================
# lib/util/apt.sh — apt wrappers
#
# Functions: apt_update_once, ensure_packages
# Globals (read):  APT_UPDATED, NETWORK_AVAILABLE
# Globals (write): APT_UPDATED
# ======================================================================

# Perform apt-get update at most once per run.
# Swallows failures and logs a warning; callers proceed with cached lists.
apt_update_once() {
  if [[ $APT_UPDATED -eq 0 ]]; then
    if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
      log_warn "Network connectivity previously reported as unavailable; attempting apt-get update regardless"
    fi
    local rc=0
    DEBIAN_FRONTEND=noninteractive apt-get update || rc=$?
    if [[ $rc -eq 0 ]]; then
      APT_UPDATED=1
    else
      log_warn "apt-get update failed (rc=$rc); proceeding with cached package lists"
    fi
  fi
  return 0
}

# Install missing packages via apt-get when required.
ensure_packages() {
  local -a missing=()
  local pkg
  for pkg in "$@"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if ((${#missing[@]} == 0)); then
    return 0
  fi
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Proceeding with package installation despite failed connectivity check"
  fi
  apt_update_once
  log_info "Installing packages: ${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}
