# ======================================================================
# lib/util/hardware.sh — Pi hardware detection
#
# Functions: detect_boot_paths, detect_boot_device, gather_system_info,
#            load_os_release
# Globals (write): CONFIG_TXT_FILE, CMDLINE_FILE, SYSTEM_MODEL,
#                  SYSTEM_PI_GEN, SYSTEM_RAM_MB, SYSTEM_BOOT_DEVICE,
#                  SYSTEM_KERNEL, SYSTEM_FIRMWARE, SYSTEM_ARCH,
#                  OS_ID, OS_ID_LIKE, OS_CODENAME
# ======================================================================
# Globals populated below are consumed by the main script and other util
# modules; shellcheck cannot see across source boundaries.
# shellcheck disable=SC2034

# Populate OS identification fields from /etc/os-release.
load_os_release() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID=${ID:-raspbian}
    OS_CODENAME=${VERSION_CODENAME:-bookworm}
    OS_ID_LIKE=${ID_LIKE:-debian}
  else
    OS_ID="raspbian"
    OS_CODENAME="bookworm"
    OS_ID_LIKE="debian"
  fi
}

# Resolve the firmware config.txt / cmdline.txt paths, falling back to
# the pre-Bookworm /boot/* locations when /boot/firmware/ isn't mounted.
# If neither location has config.txt / cmdline.txt we leave the defaults
# untouched so tasks fail loudly with "config.txt missing" instead of
# silently no-opping against a bogus path.
detect_boot_paths() {
  if [[ ! -f /boot/firmware/config.txt && -f /boot/config.txt ]]; then
    CONFIG_TXT_FILE=/boot/config.txt
  fi
  if [[ ! -f /boot/firmware/cmdline.txt && -f /boot/cmdline.txt ]]; then
    CMDLINE_FILE=/boot/cmdline.txt
  fi
  # Unusual Pi image (boot partition not mounted, or custom image that
  # never shipped config.txt): warn once here rather than letting every
  # firmware task complain in turn. log_warn may not exist yet in very
  # early contexts — guard the call.
  if [[ ! -f $CONFIG_TXT_FILE && ! -f $CMDLINE_FILE ]]; then
    if command -v log_warn >/dev/null 2>&1; then
      log_warn "Neither /boot/firmware/ nor /boot/ contains config.txt/cmdline.txt; firmware tasks will skip"
    fi
  fi
}

# Infer root filesystem backing device type for logging/gating.
detect_boot_device() {
  local root_source
  root_source=$(findmnt -no SOURCE / 2>/dev/null || true)
  if [[ -z "$root_source" ]]; then
    SYSTEM_BOOT_DEVICE="unknown"
    return
  fi
  case "$root_source" in
    /dev/mmcblk*)
      SYSTEM_BOOT_DEVICE="sdcard"
      ;;
    /dev/sd*)
      SYSTEM_BOOT_DEVICE="usb"
      ;;
    /dev/nvme*)
      SYSTEM_BOOT_DEVICE="nvme"
      ;;
    PARTUUID=*)
      local partuuid resolved
      partuuid=${root_source#PARTUUID=}
      resolved=$(blkid -t "PARTUUID=$partuuid" -o device 2>/dev/null | head -n1 || true)
      if [[ -n "$resolved" ]]; then
        root_source="$resolved"
        case "$root_source" in
          /dev/mmcblk*) SYSTEM_BOOT_DEVICE="sdcard" ;;
          /dev/sd*)     SYSTEM_BOOT_DEVICE="usb" ;;
          /dev/nvme*)   SYSTEM_BOOT_DEVICE="nvme" ;;
          *)            SYSTEM_BOOT_DEVICE="$root_source" ;;
        esac
      else
        SYSTEM_BOOT_DEVICE="partuuid:$partuuid"
      fi
      ;;
    *)
      SYSTEM_BOOT_DEVICE="$root_source"
      ;;
  esac
}

# Collect model, RAM, kernel, firmware, architecture, and boot medium.
gather_system_info() {
  detect_boot_paths

  if [[ -r /proc/device-tree/model ]]; then
    # /proc/device-tree/model is NUL-terminated; some images have
    # trailing NULs, spaces, or carriage returns after "Rev 1.0". Strip
    # NUL, CR, LF, then trim leading/trailing whitespace so substring
    # matches (`*Raspberry Pi 5*`) and case-folded helpers (`is_pi500`)
    # behave consistently across Bookworm/Trixie and custom images.
    SYSTEM_MODEL=$(tr -d '\0\r\n' </proc/device-tree/model || true)
    # Bash parameter expansion trim: remove leading/trailing whitespace.
    SYSTEM_MODEL="${SYSTEM_MODEL#"${SYSTEM_MODEL%%[![:space:]]*}"}"
    SYSTEM_MODEL="${SYSTEM_MODEL%"${SYSTEM_MODEL##*[![:space:]]}"}"
  fi
  if [[ -z "$SYSTEM_MODEL" ]]; then
    SYSTEM_MODEL=$(uname -m)
  fi

  if [[ $SYSTEM_MODEL == *"Raspberry Pi 5"* || $SYSTEM_MODEL == *"Raspberry Pi 500"* ]]; then
    SYSTEM_PI_GEN="5"
  elif [[ $SYSTEM_MODEL == *"Raspberry Pi 4"* || $SYSTEM_MODEL == *"Raspberry Pi 400"* ]]; then
    SYSTEM_PI_GEN="4"
  elif [[ $SYSTEM_MODEL == *"Raspberry Pi 3"* ]]; then
    SYSTEM_PI_GEN="3"
  elif [[ $SYSTEM_MODEL == *"Raspberry Pi Zero 2"* ]]; then
    SYSTEM_PI_GEN="zero2"
  elif [[ $SYSTEM_MODEL == *"Raspberry Pi"* ]]; then
    SYSTEM_PI_GEN="other"
  else
    SYSTEM_PI_GEN="unknown"
  fi

  local mem_kb
  if mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null); then
    SYSTEM_RAM_MB=$((mem_kb / 1024))
  fi

  SYSTEM_KERNEL=$(uname -r)
  SYSTEM_ARCH=$(uname -m)

  if [[ -r /proc/device-tree/chosen/firmware/revision ]]; then
    SYSTEM_FIRMWARE=$(tr -d '\0' </proc/device-tree/chosen/firmware/revision | tr -d '\n' || true)
  fi
  if [[ -z "$SYSTEM_FIRMWARE" && -r /proc/cpuinfo ]]; then
    SYSTEM_FIRMWARE=$(awk -F': ' '/^Revision/ {print $2}' /proc/cpuinfo | head -n1)
  fi
  detect_boot_device

  log_info "Detected hardware model: ${SYSTEM_MODEL:-unknown} (Pi generation: ${SYSTEM_PI_GEN:-unknown}, RAM: ${SYSTEM_RAM_MB} MB, arch: ${SYSTEM_ARCH:-unknown})"
  log_info "Kernel: ${SYSTEM_KERNEL:-unknown}; Firmware: ${SYSTEM_FIRMWARE:-unknown}"
  if [[ -n "$SYSTEM_BOOT_DEVICE" ]]; then
    log_info "Root filesystem appears to run from: $SYSTEM_BOOT_DEVICE"
  fi
}
