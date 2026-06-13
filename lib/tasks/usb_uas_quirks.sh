# >>> pi-task
# id: usb_uas_quirks
# version: 1.1.0
# description: Disable UAS on known-broken USB-SATA adapters (auto-detect + list)
# category: storage
# default_enabled: 0
# power_sensitive: 0
# flags: --usb-uas-quirks
# gate_var: USB_UAS_QUIRKS
# reboot_required: true
# <<< pi-task

pi_task_register usb_uas_quirks \
  description="Disable UAS on known-broken USB-SATA adapters (auto-detect + list)" \
  category=storage \
  version=1.1.0 \
  default_enabled=0 \
  flags="--usb-uas-quirks" \
  gate_var=USB_UAS_QUIRKS \
  reboot_required=1

# USB Attached SCSI (UAS) is the higher-performance USB storage
# protocol, but several popular USB-to-SATA bridge chips implement it
# badly enough to cause kernel I/O timeouts and disconnects on the
# Pi's xHCI controller. Appending usb-storage.quirks=<VID>:<PID>:u to
# cmdline.txt downgrades the affected device to plain mass-storage —
# slower but stable.
#
# Two input paths:
#   --usb-uas-quirks            auto-detect from lsusb against the
#                               built-in list of problem chips.
#   USB_UAS_EXTRA="VID:PID,..."  additional pairs the operator knows
#                               about; appended alongside auto-detect.
#
# Auto-detect list (every pair confirmed in raspberrypi/linux issues
# or the Pi forums as needing the `u` quirk):
#   152d:0578   JMicron JMS578 SATA 6Gb/s bridge
#   152d:0567   JMicron JMS567
#   152d:0583   JMicron JMS583 NVMe bridge
#   174c:55aa   ASMedia ASM1153E SATA 6Gb/s bridge
#   2109:0715   VIA Labs VL715 USB3 SATA
#   0bda:9210   Realtek RTL9210 NVMe bridge
_USB_UAS_KNOWN_BAD=(
  "152d:0578"
  "152d:0567"
  "152d:0583"
  "174c:55aa"
  "2109:0715"
  "0bda:9210"
)

_usb_uas_detect() {
  local -a hits=()
  local vid_pid line
  if command -v lsusb >/dev/null 2>&1; then
    while read -r line; do
      # lsusb output: "Bus 002 Device 004: ID 152d:0578 JMicron …"
      vid_pid=$(awk '{for(i=1;i<=NF;i++) if ($i=="ID") { print $(i+1); exit } }' <<<"$line")
      [[ -z "$vid_pid" ]] && continue
      local known
      for known in "${_USB_UAS_KNOWN_BAD[@]}"; do
        if [[ "${vid_pid,,}" == "${known,,}" ]]; then
          hits+=("$known:u")
          break
        fi
      done
    done < <(lsusb 2>/dev/null)
  fi
  if [[ -n "${USB_UAS_EXTRA:-}" ]]; then
    local extra
    IFS=',' read -ra extra <<< "$USB_UAS_EXTRA"
    for vid_pid in "${extra[@]}"; do
      vid_pid=${vid_pid//[[:space:]]/}
      [[ "$vid_pid" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}(:[a-z]+)?$ ]] || continue
      # Accept bare VID:PID and append :u ourselves; pass through if
      # the operator already supplied a quirks suffix.
      [[ "$vid_pid" == *:*:* ]] || vid_pid="${vid_pid}:u"
      hits+=("$vid_pid")
    done
  fi
  # Dedupe.
  local -A seen=()
  local out=""
  for vid_pid in "${hits[@]}"; do
    [[ -n "${seen[$vid_pid]:-}" ]] && continue
    seen[$vid_pid]=1
    [[ -n "$out" ]] && out+=","
    out+="$vid_pid"
  done
  printf '%s' "$out"
}

# Union two comma-separated quirks lists, preserving order (existing
# entries first, then newly-detected). usb-storage.quirks is a single
# kernel module parameter, so an existing token already in cmdline.txt
# must be merged with — not clobbered or duplicated by — what we detect
# this run; otherwise a pre-existing quirk (or one for an adapter that
# happens to be unplugged this boot) is silently dropped.
_usb_uas_merge() {
  local existing=$1 detected=$2
  local -A seen=()
  local out="" item
  local -a items=()
  IFS=',' read -ra items <<< "$existing"
  local -a more=()
  IFS=',' read -ra more <<< "$detected"
  items+=("${more[@]}")
  for item in "${items[@]}"; do
    item=${item//[[:space:]]/}
    [[ -z "$item" ]] && continue
    [[ -n "${seen[$item]:-}" ]] && continue
    seen[$item]=1
    [[ -n "$out" ]] && out+=","
    out+="$item"
  done
  printf '%s' "$out"
}

run_usb_uas_quirks() {
  if [[ ${USB_UAS_QUIRKS:-0} -eq 0 ]]; then
    log_info "USB UAS quirks not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if [[ ! -f "$CMDLINE_FILE" ]]; then
    log_warn "cmdline.txt not present; cannot set USB quirks"
    pi_skip_reason "cmdline.txt missing"
    return 2
  fi
  local quirks
  quirks=$(_usb_uas_detect)
  if [[ -z "$quirks" ]]; then
    log_info "No known-bad USB-SATA adapters attached and USB_UAS_EXTRA unset; nothing to quirk"
    pi_skip_reason "no affected devices detected"
    return 2
  fi
  backup_file "$CMDLINE_FILE"
  # Merge with any existing usb-storage.quirks= token and write exactly
  # one (cmdline_set_kv replaces by key). cmdline_ensure_token would have
  # appended a second token, and the kernel keeps only the last — silently
  # dropping a pre-existing quirk or one for an unplugged adapter.
  local existing merged
  existing=$(cmdline_get_value "usb-storage.quirks" "$CMDLINE_FILE" 2>/dev/null || true)
  merged=$(_usb_uas_merge "$existing" "$quirks")
  local rc=0
  cmdline_set_kv "usb-storage.quirks" "$merged" "$CMDLINE_FILE" || rc=$?
  case $rc in
    0) log_info "Applied usb-storage.quirks=$merged (reboot required)" ;;
    1) log_info "usb-storage.quirks=$merged already present in cmdline.txt" ;;
    *) log_warn "Failed to write USB quirks to cmdline.txt"; return 1 ;;
  esac
  write_json_field "$CONFIG_OPTIMISER_STATE" "storage.uas_quirks" "$merged"
}

pi_preview_usb_uas_quirks() {
  [[ ${USB_UAS_QUIRKS:-0} -eq 0 ]] && return 0
  local quirks
  quirks=$(_usb_uas_detect)
  [[ -z "$quirks" ]] && return 0
  local target=${CMDLINE_FILE:-/boot/firmware/cmdline.txt}
  local existing merged
  existing=$(cmdline_get_value "usb-storage.quirks" "$target" 2>/dev/null || true)
  merged=$(_usb_uas_merge "$existing" "$quirks")
  cmdline_set_kv "usb-storage.quirks" "$merged" "$target" >/dev/null 2>&1 || true
}
