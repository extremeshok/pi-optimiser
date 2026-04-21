# ======================================================================
# lib/util/preflight.sh — throttle/temperature/disk/network preflight
#
# Functions: describe_throttle_bits, preflight_checks, apt_lock_in_use
# Globals (write): PRECHECK_WARNINGS, PRECHECK_BLOCKERS, POWER_HEALTHY,
#                  POWER_HISTORY_CLEAN, NETWORK_AVAILABLE, APT_LOCK_BUSY
# ======================================================================
# shellcheck disable=SC2034

# Return 0 if another process holds any of the apt/dpkg frontend or
# database locks. Uses fuser when available, falls back to lsof, then to
# a last-ditch `apt-get check --dry-run` which surfaces "could not get
# lock" when frontends collide. Callers treat a positive result as a
# transient "retry or abort" signal rather than a hard permission error.
apt_lock_in_use() {
  local lock
  local -a locks=(
    /var/lib/dpkg/lock
    /var/lib/dpkg/lock-frontend
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  if command -v fuser >/dev/null 2>&1; then
    for lock in "${locks[@]}"; do
      [[ -e $lock ]] || continue
      # fuser exits 0 iff something holds the file; swallow stderr so
      # the "no process found" line doesn't leak into logs.
      if fuser "$lock" >/dev/null 2>&1; then
        return 0
      fi
    done
    return 1
  fi
  if command -v lsof >/dev/null 2>&1; then
    for lock in "${locks[@]}"; do
      [[ -e $lock ]] || continue
      if lsof -- "$lock" >/dev/null 2>&1; then
        return 0
      fi
    done
    return 1
  fi
  # Best-effort final fallback: a running dpkg/apt frontend makes the
  # dry-run check fail with a recognisable message. Unknown errors are
  # treated as "not locked" so we don't block on a broken apt config.
  if command -v apt-get >/dev/null 2>&1; then
    local out
    out=$(LC_ALL=C apt-get check 2>&1 >/dev/null || true)
    if [[ $out == *"Could not get lock"* || $out == *"Unable to lock"* ]]; then
      return 0
    fi
  fi
  return 1
}

# Translate vcgencmd throttle bitmask into readable text.
describe_throttle_bits() {
  local value=$1
  local -a messages=()
  ((value & 0x1))     && messages+=("under-voltage (present)")
  ((value & 0x2))     && messages+=("arm frequency capped (present)")
  ((value & 0x4))     && messages+=("currently throttled")
  ((value & 0x8))     && messages+=("soft temp limit (present)")
  ((value & 0x10000)) && messages+=("under-voltage occurred")
  ((value & 0x20000)) && messages+=("frequency capping occurred")
  ((value & 0x40000)) && messages+=("throttle occurred")
  ((value & 0x80000)) && messages+=("soft temp limit occurred")
  if ((${#messages[@]} == 0)); then
    echo "no throttle flags set"
  else
    printf '%s' "${messages[*]}"
  fi
}

# Run power, thermal, disk, and connectivity checks before tasks.
preflight_checks() {
  PRECHECK_WARNINGS=()
  PRECHECK_BLOCKERS=()
  POWER_HEALTHY=1
  # POWER_HISTORY_CLEAN tracks whether the *historical* undervoltage /
  # throttle / soft-temp bits (0x10000 / 0x40000 / 0x80000) are clear.
  # Overclock-style tasks check this in addition to POWER_HEALTHY so a
  # Pi that recently browned out doesn't get pushed further.
  POWER_HISTORY_CLEAN=1
  NETWORK_AVAILABLE=1
  APT_LOCK_BUSY=0

  log_info "Running preflight checks"

  if command -v vcgencmd >/dev/null 2>&1; then
    local throttled_raw throttled_hex throttled_val temp_raw temp_c
    throttled_raw=$(vcgencmd get_throttled 2>/dev/null || true)
    if [[ $throttled_raw =~ (0x[0-9a-fA-F]+) ]]; then
      throttled_hex=${BASH_REMATCH[1]}
      throttled_val=$((16#${throttled_hex#0x}))
      local description
      description=$(describe_throttle_bits "$throttled_val")
      if ((throttled_val == 0)); then
        log_info "  Power/Thermal: OK (throttled=$throttled_hex)"
      else
        log_warn "  Power/Thermal: throttled flag $throttled_hex -> $description"
        # Current under-voltage (0x1), frequency cap (0x2), throttle
        # (0x4), or soft temp limit (0x8) are all present-tense faults —
        # block power-sensitive tasks.
        if ((throttled_val & 0x1)) || ((throttled_val & 0x2)) \
           || ((throttled_val & 0x4)) || ((throttled_val & 0x8)); then
          POWER_HEALTHY=0
          PRECHECK_BLOCKERS+=("Power or thermal issue detected (throttled=$throttled_hex)")
        else
          PRECHECK_WARNINGS+=("Historical throttle detected (throttled=$throttled_hex)")
        fi
        # Historical bits (occurred-since-boot): 0x10000 undervoltage,
        # 0x40000 throttle, 0x80000 soft-temp. Flip POWER_HISTORY_CLEAN
        # so overclock/firmware tasks that would further stress the
        # PMIC can decline even when the rail is healthy right now.
        if ((throttled_val & 0x10000)) || ((throttled_val & 0x40000)) \
           || ((throttled_val & 0x80000)); then
          POWER_HISTORY_CLEAN=0
        fi
      fi
    else
      PRECHECK_WARNINGS+=("Unable to parse vcgencmd get_throttled output: $throttled_raw")
    fi

    temp_raw=$(vcgencmd measure_temp 2>/dev/null || true)
    if [[ $temp_raw =~ =([0-9.]+) ]]; then
      temp_c=${BASH_REMATCH[1]}
      log_info "  Reported SoC temperature: ${temp_c}°C"
      if (( ${temp_c%.*} >= 80 )); then
        PRECHECK_WARNINGS+=("SoC temperature ${temp_c}°C is near throttle range")
      fi
    fi
  else
    PRECHECK_WARNINGS+=("vcgencmd not available; skipping power/thermal checks")
  fi

  local free_mb
  if free_mb=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}'); then
    if (( free_mb < 512 )); then
      PRECHECK_WARNINGS+=("Root filesystem low on space (${free_mb}MB available)")
    fi
  fi

  if command -v ping >/dev/null 2>&1; then
    if ! ping -c1 -W2 8.8.8.8 >/dev/null 2>&1 && ! ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
      NETWORK_AVAILABLE=0
      PRECHECK_WARNINGS+=("Network connectivity test failed; apt operations may fail")
    fi
  fi

  # apt/dpkg lock guard. unattended-upgrades commonly runs right after
  # boot; starting an apt-get update while it holds the frontend lock
  # hangs for minutes then dies. Surface as a warning now so tasks that
  # would install packages can short-circuit cleanly.
  if apt_lock_in_use; then
    APT_LOCK_BUSY=1
    PRECHECK_WARNINGS+=("apt/dpkg lock held by another process (likely unattended-upgrades); package tasks may skip")
  fi

  # 64-bit enforcement. README advertises 64-bit-only; overclock / EEPROM
  # / firmware-update paths assume aarch64 registers and will silently
  # misbehave on a 32-bit kernel running on a Pi with 64-bit firmware.
  # We don't hard-exit (non-Pi hosts still want `pi-optimiser --status`
  # and generic Linux tasks to work) but we *do* mark power-sensitive
  # tasks unsafe so overclock/EEPROM won't be attempted.
  case "${SYSTEM_ARCH:-$(uname -m)}" in
    aarch64|arm64|x86_64|amd64) : ;;
    armv7l|armv6l|armv5*)
      POWER_HEALTHY=0
      PRECHECK_BLOCKERS+=("32-bit kernel (${SYSTEM_ARCH:-$(uname -m)}) detected; pi-optimiser requires 64-bit Raspberry Pi OS for overclock / EEPROM / firmware tasks")
      ;;
  esac

  if ((${#PRECHECK_BLOCKERS[@]} > 0)); then
    local item
    for item in "${PRECHECK_BLOCKERS[@]}"; do
      log_warn "  Blocker: $item"
    done
  else
    log_info "  Blockers: none"
  fi

  if ((${#PRECHECK_WARNINGS[@]} > 0)); then
    local warn
    for warn in "${PRECHECK_WARNINGS[@]}"; do
      log_warn "  Warning: $warn"
    done
  else
    log_info "  Warnings: none"
  fi
}
