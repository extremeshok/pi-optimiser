# >>> pi-task
# id: hailo
# version: 1.1.0
# description: Install Hailo NPU drivers for Raspberry Pi Hailo hardware (Pi 5)
# category: integrations
# default_enabled: 0
# power_sensitive: 0
# flags: --install-hailo,--hailo-hardware
# gate_var: INSTALL_HAILO
# reboot_required: true
# <<< pi-task

pi_task_register hailo \
  description="Install Hailo NPU drivers for Raspberry Pi Hailo hardware (Pi 5)" \
  category=integrations \
  version=1.1.0 \
  default_enabled=0 \
  flags="--install-hailo,--hailo-hardware" \
  gate_var=INSTALL_HAILO \
  reboot_required=1

_hailo_pkg_installed() {
  local pkg=$1
  dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -qx 'install ok installed'
}

_hailo_label() {
  case $1 in
    hat)  printf '%s\n' "Kit / HAT+ (hailo-all)" ;;
    hat2) printf '%s\n' "HAT+ 2 (hailo-h10-all)" ;;
    *)    printf '%s\n' "$1" ;;
  esac
}

_hailo_normalize_hardware() {
  local hw=${1:-auto}
  hw=${hw,,}
  case $hw in
    auto|hat|hat2)
      printf '%s\n' "$hw"
      ;;
    *)
      return 1
      ;;
  esac
}

_hailo_detect_hardware() {
  if _hailo_pkg_installed hailo-h10-all; then
    printf '%s\n' "hat2"
    return 0
  fi
  if _hailo_pkg_installed hailo-all || _hailo_pkg_installed hailo-dkms; then
    printf '%s\n' "hat"
    return 0
  fi
  if command -v lspci >/dev/null 2>&1; then
    local pci
    pci=$(lspci -nn 2>/dev/null | grep -i 'hailo' || true)
    if [[ -n "$pci" ]]; then
      if grep -Eiq 'Hailo-10H|Hailo[[:space:]-]?10' <<<"$pci"; then
        printf '%s\n' "hat2"
        return 0
      fi
      if grep -Eiq 'Hailo-8L?|Hailo[[:space:]-]?8' <<<"$pci"; then
        printf '%s\n' "hat"
        return 0
      fi
      return 2
    fi
  fi
  return 1
}

# Raspberry Pi currently ships two mutually-exclusive Hailo package
# families:
#   hat  -> hailo-all      for Kit / HAT+
#   hat2 -> hailo-h10-all  for HAT+ 2
#
# The default CLI mode is `--hailo-hardware auto`. Auto installs only
# when an installed package or PCIe probe identifies the Hailo family;
# explicit `hat` / `hat2` keeps image-prep workflows possible.
run_hailo() {
  if [[ ${INSTALL_HAILO:-0} -eq 0 ]]; then
    log_info "Hailo NPU driver install not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if ! is_pi5; then
    log_info "Hailo NPU hardware is Pi 5 / Pi 500 only; skipping on ${SYSTEM_MODEL:-unknown}"
    pi_skip_reason "model unsupported"
    return 2
  fi

  local requested hardware detect_rc=0
  if ! requested=$(_hailo_normalize_hardware "${HAILO_HARDWARE:-auto}"); then
    log_error "Unsupported Hailo hardware selection: ${HAILO_HARDWARE:-}"
    return 1
  fi
  hardware=$requested
  if [[ $requested == "auto" ]]; then
    hardware=$(_hailo_detect_hardware) || detect_rc=$?
    case $detect_rc in
      0)
        log_info "Detected Hailo hardware family: $(_hailo_label "$hardware")"
        ;;
      2)
        log_warn "Hailo device detected on PCIe, but the hardware family is unknown"
        log_warn "Re-run with --hailo-hardware hat or --hailo-hardware hat2 if you know the board"
        pi_skip_reason "unknown Hailo hardware"
        return 2
        ;;
      *)
        log_info "No Hailo hardware detected; auto mode is skipping driver installation"
        log_info "For image preparation without attached hardware, pass --hailo-hardware hat or hat2"
        pi_skip_reason "no Hailo hardware detected"
        return 2
        ;;
    esac
  else
    log_info "Using requested Hailo hardware family: $(_hailo_label "$hardware")"
  fi

  # Kernel version guard. hailo-dkms refuses to build on < 6.6.31.
  local kver
  kver=$(uname -r 2>/dev/null | awk -F'[.-]' '{printf "%d.%d.%d", $1, $2, $3}')
  if [[ -n "$kver" ]]; then
    local major minor patch
    IFS='.' read -r major minor patch <<< "$kver"
    if (( major < 6 )) || { (( major == 6 )) && (( minor < 6 )); } \
       || { (( major == 6 )) && (( minor == 6 )) && (( patch < 31 )); }; then
      log_warn "Kernel $kver is older than 6.6.31; hailo-dkms will likely fail to build"
      log_warn "Run 'sudo apt full-upgrade && sudo reboot' first, then re-run with --install-hailo"
    fi
  fi

  # PCIe Gen 3 is only needed for the older M.2 Kit; the HAT+ boards
  # apply their own PCIe tuning. We cannot reliably distinguish Kit vs
  # HAT+ from lspci, so keep this as an informational tip for hailo-all.
  if [[ $hardware == "hat" && ${INSTALL_PCIE_GEN3:-0} -ne 1 ]]; then
    log_info "Tip: Hailo Kit users should pair this with --pcie-gen3 for full throughput"
  fi

  local pkg
  case $hardware in
    hat)
      pkg="hailo-all"
      if _hailo_pkg_installed hailo-h10-all; then
        log_error "hailo-h10-all is already installed; it cannot co-exist with hailo-all"
        log_error "Remove the conflicting package manually, then re-run --hailo-hardware hat"
        return 1
      fi
      ;;
    hat2)
      pkg="hailo-h10-all"
      if _hailo_pkg_installed hailo-all; then
        log_error "hailo-all is already installed; it cannot co-exist with hailo-h10-all"
        log_error "Remove the conflicting package manually, then re-run --hailo-hardware hat2"
        return 1
      fi
      ;;
    *)
      log_error "Internal error: unknown Hailo hardware family '$hardware'"
      return 1
      ;;
  esac

  if ensure_packages dkms "$pkg"; then
    log_info "Installed $pkg package family"
  else
    if [[ $hardware == "hat" ]]; then
      log_info "hailo-all not available; falling back to split Hailo packages"
      if ! ensure_packages dkms hailort hailo-dkms python3-hailort hailo-tappas-core hailofw; then
        log_warn "Failed to install the Hailo runtime packages"
        return 1
      fi
    else
      log_warn "Failed to install $pkg"
      return 1
    fi
  fi

  # DKMS may be queued for a kernel build; surface its state so the
  # operator knows whether a reboot is needed before inference works.
  if command -v dkms >/dev/null 2>&1; then
    local dkms_status
    dkms_status=$(dkms status 2>/dev/null | grep -i hailo | head -n1 || true)
    if [[ -n "$dkms_status" ]]; then
      log_info "DKMS: $dkms_status"
    fi
  fi

  log_info "Hailo driver stack installed. Reboot required."
  log_info "Next:"
  log_info "  1. Reboot so the DKMS module loads against the running kernel."
  log_info "  2. Verify with 'hailortcli fw-control identify' (or ls /dev/hailo*)."
  write_json_field "$CONFIG_OPTIMISER_STATE" "integrations.hailo" "$hardware"
  write_json_field "$CONFIG_OPTIMISER_STATE" "integrations.hailo_package" "$pkg"
}
