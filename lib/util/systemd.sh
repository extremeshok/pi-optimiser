# ======================================================================
# lib/util/systemd.sh — systemd unit helpers
#
# Functions: unit_exists, unit_disable_now, unit_mask, remount_path
# ======================================================================

# Check whether a systemd unit definition exists.
unit_exists() {
  systemctl list-unit-files "$1" >/dev/null 2>&1
}

# Disable and stop a systemd unit if present.
unit_disable_now() {
  local unit=$1
  if ! unit_exists "$unit"; then
    return
  fi
  if ! systemctl disable --now "$unit" >/dev/null 2>&1; then
    log_warn "Unable to disable $unit"
  else
    log_info "Disabled $unit"
  fi
}

# Mask a systemd unit to prevent activation.
unit_mask() {
  local unit=$1
  if ! unit_exists "$unit"; then
    return
  fi
  if ! systemctl mask "$unit" >/dev/null 2>&1; then
    log_warn "Unable to mask $unit"
  else
    log_info "Masked $unit"
  fi
}

# Attempt to remount a path to apply updated options.
remount_path() {
  local path=$1
  if mountpoint -q "$path"; then
    if ! mount -o remount "$path" >/dev/null 2>&1; then
      mount "$path" >/dev/null 2>&1 || true
    fi
  fi
}
