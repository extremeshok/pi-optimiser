# >>> pi-task
# id: hailo
# version: 1.0.0
# description: Install Hailo NPU drivers for Raspberry Pi Hailo hardware (Pi 5)
# category: integrations
# default_enabled: 0
# power_sensitive: 0
# flags: --install-hailo
# gate_var: INSTALL_HAILO
# <<< pi-task

pi_task_register hailo \
  description="Install Hailo NPU drivers for Raspberry Pi Hailo hardware (Pi 5)" \
  category=integrations \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-hailo" \
  gate_var=INSTALL_HAILO

# Raspberry Pi Hailo HAT hardware attaches a Hailo-8(L|R) NPU over
# PCIe. The stack is shipped in Raspberry Pi OS as the `hailo-all`
# metapackage, which pulls:
#   - hailo-dkms            kernel module (needs the kernel headers)
#   - hailort               userspace runtime
#   - python3-hailort       Python bindings
#   - hailo-tappas-core     post-processing library
#   - hailofw               NPU firmware
#
# Prerequisites that this task verifies (and warns about) rather
# than silently failing on:
#   - Pi 5 / Pi 500 only (the PCIe connector only exists there).
#   - Kernel 6.6.31+ (the DKMS module fails to build on older).
#   - PCIe Gen 3 helps throughput but isn't mandatory.
#   - Actual NPU visible via lspci (we warn if not; install still
#     proceeds because the operator may be prepping an image).
#
# Pairing the NPU (downloading models, running inference) is outside
# this task. The Raspberry Pi and Hailo docs cover model setup.
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

  # Hardware probe — informational only; don't block install.
  if command -v lspci >/dev/null 2>&1; then
    if lspci 2>/dev/null | grep -qi 'hailo'; then
      log_info "Hailo NPU detected on PCIe"
    else
      log_warn "No Hailo device reported by lspci; installing drivers anyway (OK for image prep)"
    fi
  fi

  # Suggest PCIe Gen 3 for HAT+ users; not an error.
  if [[ ${INSTALL_PCIE_GEN3:-0} -ne 1 ]]; then
    log_info "Tip: pair with --pcie-gen3 for full Hailo HAT throughput (optional)"
  fi

  # Install the metapackage. Upstream occasionally ships it as a
  # monolithic `hailo-all`; older Bookworm images only had the
  # individual components. Try the metapackage first, fall back to
  # the split list documented by Raspberry Pi.
  if ensure_packages hailo-all; then
    log_info "Installed hailo-all metapackage"
  else
    log_info "hailo-all not available; falling back to split packages"
    if ! ensure_packages hailort hailo-dkms python3-hailort hailo-tappas-core hailofw; then
      log_warn "Failed to install the Hailo runtime packages"
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

  log_info "Hailo driver stack installed. Next:"
  log_info "  1. Reboot so the DKMS module loads against the running kernel."
  log_info "  2. Verify with 'hailortcli fw-control identify' (or ls /dev/hailo*)."
  log_info "  3. Follow the Raspberry Pi and Hailo model setup guides."
  write_json_field "$CONFIG_OPTIMISER_STATE" "integrations.hailo" "installed"
  pi_mark_reboot_required hailo
}
