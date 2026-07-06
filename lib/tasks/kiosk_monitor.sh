# >>> pi-task
# id: kiosk_monitor
# version: 1.3.0
# description: Install kiosk-monitor, the self-healing fullscreen kiosk watchdog
# category: display
# default_enabled: 0
# power_sensitive: 0
# flags: --install-kiosk-monitor
# gate_var: INSTALL_KIOSK_MONITOR
# refresh_days: always
# <<< pi-task

pi_task_register kiosk_monitor \
  description="Install kiosk-monitor, the self-healing fullscreen kiosk watchdog" \
  category=display \
  version=1.3.0 \
  default_enabled=0 \
  flags="--install-kiosk-monitor" \
  gate_var=INSTALL_KIOSK_MONITOR \
  refresh_days=always

# kiosk-monitor (https://github.com/extremeshok/kiosk-monitor) launches
# fullscreen Chromium or VLC on one or two HDMI displays and acts as a
# self-healing watchdog: it detects per-display freezes and restarts a
# stalled instance automatically. It targets Raspberry Pi OS trixie
# (Debian 13) Desktop or newer, on a labwc Wayland session (X11 rpd-x is
# a supported fallback).
#
# The upstream kiosk-monitor.sh is both the installer and the runtime.
# Once installed, `kiosk-monitor --version` reports the local version;
# the raw upstream script carries SCRIPT_VERSION; and `--update` applies
# a newer script only when one exists.
# First install uses `--install`, which copies it to
# /usr/local/bin/kiosk-monitor, writes a default config at
# /etc/kiosk-monitor/kiosk-monitor.conf, pulls its runtime deps
# (chromium/vlc/grim/wlr-randr/...), and creates+enables the service.
# We fetch that first-run installer over a hardened TLS channel
# (pi_curl_secure) to a temp file and run it from disk rather than the
# blind `curl | bash` the upstream README suggests.
#
# Like pi_connect (which leaves `rpi-connect signin` to the operator),
# this task installs the tool but leaves the screen URL/mode to a
# deliberate follow-up step: `sudo kiosk-monitor --reconfig`, or edit
# /etc/kiosk-monitor/kiosk-monitor.conf then `systemctl restart
# kiosk-monitor`. The `kiosk` profile enables this task.
#
# Upstream publishes no git tags yet, so the installer tracks the default
# branch. A security-conscious operator can pin to a tag or commit SHA
# once one exists by exporting KIOSK_MONITOR_INSTALL_REF=<ref> (mirrors
# pi-optimiser's own PI_OPTIMISER_REF). The ref is validated with
# validate_git_ref before it is interpolated into the download URL.
KIOSK_MONITOR_INSTALL_REF="${KIOSK_MONITOR_INSTALL_REF:-main}"

_kiosk_monitor_remote_version() {
  local install_url=$1 tmp remote_version=""
  tmp=$(mktemp) || return 1
  if pi_curl_secure "$install_url" -o "$tmp" && [[ -s "$tmp" ]]; then
    remote_version=$(grep -m1 '^SCRIPT_VERSION=' "$tmp" | sed -E 's/^SCRIPT_VERSION="?([^"]+)"?.*$/\1/')
  fi
  rm -f "$tmp"
  [[ -n "$remote_version" ]] || return 1
  printf '%s\n' "$remote_version"
}

_kiosk_monitor_local_version() {
  local local_version=""
  local_version=$(kiosk-monitor --version 2>/dev/null | head -n1 | sed -E 's/.*version:?[[:space:]]*//; s/^[^0-9]*//' || true)
  [[ -n "$local_version" ]] || return 1
  printf '%s\n' "$local_version"
}

_version_gt() {
  local candidate=$1 current=$2
  CANDIDATE_VERSION="$candidate" CURRENT_VERSION="$current" run_python <<'PY'
import os
import re
import sys

def parts(value):
    nums = [int(x) for x in re.findall(r"\d+", value)]
    return nums or [0]

candidate = parts(os.environ["CANDIDATE_VERSION"])
current = parts(os.environ["CURRENT_VERSION"])
width = max(len(candidate), len(current))
candidate += [0] * (width - len(candidate))
current += [0] * (width - len(current))
sys.exit(0 if candidate > current else 1)
PY
}

_kiosk_monitor_update_if_needed() {
  local install_url=$1 local_version remote_version
  local_version=$(_kiosk_monitor_local_version) || {
    local check_output check_rc=0 line
    log_warn "kiosk-monitor: unable to read installed version; running built-in update check"
    check_output=$(kiosk-monitor --update --check 2>&1) || check_rc=$?
    while IFS= read -r line; do
      [[ -n "$line" ]] && log_info "kiosk-monitor: $line"
    done <<< "$check_output"
    if [[ $check_rc -ne 0 ]]; then
      log_error "kiosk-monitor --update --check failed"
      return 1
    fi
    if grep -Eiq 'update available|newer' <<<"$check_output"; then
      log_info "kiosk-monitor update available; running kiosk-monitor --update"
      kiosk-monitor --update || return 1
    fi
    return 0
  }
  remote_version=$(_kiosk_monitor_remote_version "$install_url") || {
    log_error "kiosk-monitor: unable to determine remote version"
    return 1
  }
  log_info "kiosk-monitor installed version: $local_version"
  log_info "kiosk-monitor remote version: $remote_version"
  write_json_field "$CONFIG_OPTIMISER_STATE" "display.kiosk_monitor_last_check" \
    "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
  if _version_gt "$remote_version" "$local_version"; then
    log_info "kiosk-monitor update available; running kiosk-monitor --update"
    if ! kiosk-monitor --update; then
      log_error "kiosk-monitor --update failed"
      return 1
    fi
    write_json_field "$CONFIG_OPTIMISER_STATE" "display.kiosk_monitor_last_update" \
      "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
  else
    log_info "kiosk-monitor is already current"
  fi
}

run_kiosk_monitor() {
  if [[ ${INSTALL_KIOSK_MONITOR:-0} -eq 0 ]]; then
    log_info "kiosk-monitor not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  # Fail fast offline: install and upgrade both download over HTTPS.
  # Running offline would leave a half-state.
  if [[ ${NETWORK_AVAILABLE:-1} -eq 0 ]]; then
    log_warn "Network unavailable; cannot download kiosk-monitor"
    pi_skip_reason "network unavailable"
    return 2
  fi

  local kiosk_bin=/usr/local/bin/kiosk-monitor
  local kiosk_service=/etc/systemd/system/kiosk-monitor.service
  local kiosk_conf=/etc/kiosk-monitor/kiosk-monitor.conf
  if ! validate_git_ref "$KIOSK_MONITOR_INSTALL_REF"; then
    log_error "kiosk-monitor: invalid KIOSK_MONITOR_INSTALL_REF '$KIOSK_MONITOR_INSTALL_REF'"
    return 1
  fi
  local install_url="https://raw.githubusercontent.com/extremeshok/kiosk-monitor/${KIOSK_MONITOR_INSTALL_REF}/kiosk-monitor.sh"
  if command -v kiosk-monitor >/dev/null 2>&1; then
    local kiosk_path
    kiosk_path=$(command -v kiosk-monitor)
    log_info "kiosk-monitor already installed at $kiosk_path; checking for updates"
    _kiosk_monitor_update_if_needed "$install_url" || return 1
    write_json_field "$CONFIG_OPTIMISER_STATE" "display.kiosk_monitor" "installed"
    return 0
  fi

  # Informational only — don't block. kiosk-monitor needs a desktop
  # session to drive a display; on a Lite image the operator may be
  # prepping for a later desktop install (mirrors the hailo image-prep
  # philosophy of warn-then-proceed).
  load_os_release
  if [[ -n ${OS_CODENAME:-} && ${OS_CODENAME} != "trixie" ]]; then
    log_warn "kiosk-monitor targets Raspberry Pi OS trixie (Debian 13) Desktop or newer; detected '${OS_CODENAME}' — installing anyway"
  fi

  ensure_packages ca-certificates curl

  # Register the files the installer creates BEFORE it runs so
  # `--undo kiosk_monitor` removes them even on a partial run.
  record_created "$kiosk_bin"
  record_created "$kiosk_service"
  record_created "$kiosk_conf"

  local tmp_installer
  tmp_installer=$(mktemp) || { log_error "kiosk-monitor: mktemp failed"; return 1; }
  # shellcheck disable=SC2064  # expand tmp path now, not at trap-fire time
  trap "rm -f \"$tmp_installer\"" RETURN

  if ! pi_curl_secure "$install_url" -o "$tmp_installer"; then
    log_error "kiosk-monitor: failed to download installer from $install_url"
    return 1
  fi
  if [[ ! -s "$tmp_installer" ]]; then
    log_error "kiosk-monitor: downloaded installer is empty"
    return 1
  fi

  if ! bash "$tmp_installer" --install; then
    log_error "kiosk-monitor: installer exited non-zero"
    return 1
  fi

  if command -v kiosk-monitor >/dev/null 2>&1; then
    log_info "kiosk-monitor installed at $(command -v kiosk-monitor)"
    log_info "Configure the screen URL/mode: run 'sudo kiosk-monitor --reconfig'"
    log_info "  (or edit $kiosk_conf then 'sudo systemctl restart kiosk-monitor')"
  else
    log_warn "kiosk-monitor installer completed but the binary was not found on PATH"
  fi
  write_json_field "$CONFIG_OPTIMISER_STATE" "display.kiosk_monitor" "installed"
}
