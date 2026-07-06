# >>> pi-task
# id: usb_gadget
# version: 1.0.0
# description: Enable or disable Raspberry Pi USB Ethernet gadget mode
# category: network
# default_enabled: 0
# power_sensitive: 0
# flags: --enable-usb-gadget,--disable-usb-gadget
# gate_var: USB_GADGET_SET
# reboot_required: true
# <<< pi-task

pi_task_register usb_gadget \
  description="Enable or disable Raspberry Pi USB Ethernet gadget mode" \
  category=network \
  version=1.0.0 \
  default_enabled=0 \
  flags="--enable-usb-gadget,--disable-usb-gadget" \
  gate_var=USB_GADGET_SET \
  reboot_required=1

_usb_gadget_mode() {
  if [[ ${USB_GADGET_DISABLE:-0} -eq 1 ]]; then
    printf '%s\n' "disable"
  else
    printf '%s\n' "enable"
  fi
}

_usb_gadget_model_supported() {
  local model=${SYSTEM_MODEL,,}
  case $model in
    *"raspberry pi zero"*|\
    *"raspberry pi 3 model a"*|\
    *"raspberry pi 4 model b"*|\
    *"raspberry pi 5 model"*|\
    *"raspberry pi 500"*|\
    *"compute module 5"*)
      return 0
      ;;
  esac
  return 1
}

run_usb_gadget() {
  if [[ ${USB_GADGET_SET:-0} -eq 0 ]]; then
    log_info "USB gadget mode not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi

  local mode
  mode=$(_usb_gadget_mode)
  if [[ $mode == "enable" ]]; then
    if [[ ${OS_CODENAME:-} != "trixie" ]]; then
      log_info "USB gadget helper is supported on Raspberry Pi OS Trixie; skipping on ${OS_CODENAME:-unknown}"
      pi_skip_reason "unsupported OS release"
      return 2
    fi
    if ! _usb_gadget_model_supported; then
      log_info "USB gadget helper is not supported on ${SYSTEM_MODEL:-unknown}; skipping"
      pi_skip_reason "model unsupported"
      return 2
    fi
    if ! ensure_packages rpi-usb-gadget; then
      log_warn "Failed to install rpi-usb-gadget"
      return 1
    fi
  fi

  if ! command -v rpi-usb-gadget >/dev/null 2>&1; then
    log_info "rpi-usb-gadget command not available; nothing to ${mode}"
    pi_skip_reason "rpi-usb-gadget missing"
    return 2
  fi

  case $mode in
    enable)
      if ! rpi-usb-gadget on; then
        log_warn "rpi-usb-gadget on failed"
        return 1
      fi
      log_info "USB gadget mode enabled. Reboot required."
      write_json_field "$CONFIG_OPTIMISER_STATE" "network.usb_gadget" "enabled"
      ;;
    disable)
      if ! rpi-usb-gadget off; then
        log_warn "rpi-usb-gadget off failed"
        return 1
      fi
      log_info "USB gadget mode disabled. Reboot required."
      write_json_field "$CONFIG_OPTIMISER_STATE" "network.usb_gadget" "disabled"
      ;;
    *)
      log_error "Internal error: unsupported USB gadget mode '$mode'"
      return 1
      ;;
  esac
}
