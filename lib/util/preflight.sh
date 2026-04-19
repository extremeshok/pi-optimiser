# ======================================================================
# lib/util/preflight.sh — throttle/temperature/disk/network preflight
#
# Functions: describe_throttle_bits, preflight_checks
# Globals (write): PRECHECK_WARNINGS, PRECHECK_BLOCKERS, POWER_HEALTHY,
#                  NETWORK_AVAILABLE
# ======================================================================
# shellcheck disable=SC2034

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
  NETWORK_AVAILABLE=1

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
        if ((throttled_val & 0x1)) || ((throttled_val & 0x4)) || ((throttled_val & 0x8)); then
          POWER_HEALTHY=0
          PRECHECK_BLOCKERS+=("Power or thermal issue detected (throttled=$throttled_hex)")
        else
          PRECHECK_WARNINGS+=("Historical throttle detected (throttled=$throttled_hex)")
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
