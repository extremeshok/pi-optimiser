# ======================================================================
# lib/util/apt.sh — apt wrappers
#
# Functions: apt_update_once, ensure_packages, apt_wait_for_lock
# Globals (read):  APT_UPDATED, NETWORK_AVAILABLE, APT_LOCK_BUSY
# Globals (write): APT_UPDATED, APT_LOCK_BUSY
# ======================================================================

# Wait up to N seconds (default 30) for any concurrent apt/dpkg frontend
# to release the lock. Returns 0 if the lock is free (or never was
# taken), 1 if still busy after the timeout. Never blocks indefinitely —
# a stuck unattended-upgrades should surface as a skip reason, not a
# hung installer. apt_lock_in_use() lives in lib/util/preflight.sh.
apt_wait_for_lock() {
  local timeout=${1:-30}
  if ! declare -F apt_lock_in_use >/dev/null 2>&1; then
    return 0
  fi
  local waited=0
  while apt_lock_in_use; do
    if (( waited == 0 )); then
      log_warn "apt/dpkg lock busy; waiting up to ${timeout}s for it to release"
    fi
    if (( waited >= timeout )); then
      # shellcheck disable=SC2034  # advisory global read by preflight/diagnostics paths
      APT_LOCK_BUSY=1
      log_warn "apt/dpkg lock still held after ${timeout}s; giving up"
      return 1
    fi
    sleep 2
    waited=$(( waited + 2 ))
  done
  # shellcheck disable=SC2034  # advisory global read by preflight/diagnostics paths
  APT_LOCK_BUSY=0
  return 0
}

# Perform apt-get update at most once per run.
# Swallows failures and logs a warning; callers proceed with cached lists.
apt_update_once() {
  if [[ $APT_UPDATED -eq 0 ]]; then
    if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
      log_warn "Network connectivity previously reported as unavailable; attempting apt-get update regardless"
    fi
    # Recheck the lock right before we take it — preflight may have
    # cleared long ago and another frontend may have started since.
    apt_wait_for_lock 30 || {
      log_warn "apt-get update skipped: dpkg lock held by another process"
      return 0
    }
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
  # Second lock check — `apt-get update` may have completed while
  # unattended-upgrades started its own cycle.
  apt_wait_for_lock 60 || {
    log_warn "Cannot install ${missing[*]}: dpkg lock held by another process"
    return 1
  }
  log_info "Installing packages: ${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}
