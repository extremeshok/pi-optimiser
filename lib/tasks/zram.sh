# >>> pi-task
# id: zram
# version: 1.2.0
# description: Use compressed RAM (ZRAM) as swap instead of writing to disk
# category: storage
# default_enabled: 0
# power_sensitive: 0
# flags: --install-zram,--zram-algo
# gate_var: INSTALL_ZRAM
# <<< pi-task

# Compute ZRAM size based on RAM tier with sensible caps.
determine_zram_target_mb() {
  local ram_mb=${SYSTEM_RAM_MB:-0}
  if (( ram_mb <= 0 )); then
    echo 0
    return
  fi
  local target
  if (( ram_mb <= 2048 )); then
    target=$((ram_mb * 75 / 100))
  elif (( ram_mb <= 4096 )); then
    target=$((ram_mb * 50 / 100))
  elif (( ram_mb <= 8192 )); then
    target=$((ram_mb * 30 / 100))
  else
    target=$((ram_mb * 25 / 100))
  fi
  if (( target < 256 )); then
    target=256
  fi
  local max=$((ram_mb / 2))
  if (( max < 256 )); then
    max=256
  fi
  if (( target > max )); then
    target=$max
  fi
  echo "$target"
}

# Select preferred ZRAM compression algorithm (default lz4).
pick_zram_algorithm() {
  if [[ -n "${ZRAM_ALGO_OVERRIDE:-}" ]]; then
    echo "$ZRAM_ALGO_OVERRIDE"
    return
  fi
  echo "lz4"
}

pi_task_register zram \
  description="Use compressed RAM (ZRAM) as swap instead of writing to disk" \
  category=storage \
  version=1.2.0 \
  default_enabled=0 \
  flags="--install-zram,--zram-algo" \
  gate_var=INSTALL_ZRAM

run_zram() {
  if [[ $ZRAM_ALGO_OVERRIDE == "disabled" ]]; then
    local removed=0
    if [[ -f "$ZRAM_CONF_FILE" ]]; then
      backup_file "$ZRAM_CONF_FILE"
      rm -f "$ZRAM_CONF_FILE"
      removed=1
    fi
    if systemctl list-unit-files systemd-zram-setup@.service >/dev/null 2>&1; then
      systemctl disable --now systemd-zram-setup@zram0 >/dev/null 2>&1 || log_warn "Unable to disable systemd-zram-setup@zram0"
    fi
    swapoff /dev/zram0 >/dev/null 2>&1 || true
    write_json_field "$CONFIG_OPTIMISER_STATE" "zram.size_mb" "disabled"
    write_json_field "$CONFIG_OPTIMISER_STATE" "zram.algorithm" "disabled"
    write_json_field "$CONFIG_OPTIMISER_STATE" "zram.last_configured" "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
    if (( removed == 1 )); then
      log_info "Disabled ZRAM and removed $ZRAM_CONF_FILE"
    else
      log_info "ZRAM already disabled"
    fi
    return 0
  fi

  if [[ $INSTALL_ZRAM -eq 0 ]]; then
    log_info "ZRAM not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi

  local size_mb algo
  size_mb=$(determine_zram_target_mb)
  if (( size_mb <= 0 )); then
    log_warn "Unable to determine a suitable ZRAM size; skipping"
    pi_skip_reason "no RAM info"
    return 2
  fi

  algo=$(pick_zram_algorithm)
  if [[ $algo == "disabled" ]]; then
    log_warn "ZRAM algorithm set to disabled; skipping configuration"
    pi_skip_reason "algorithm disabled"
    return 2
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    log_info "[dry-run] Would configure systemd zram generator for ${size_mb}MB swap (algo $algo)"
    return 0
  fi

  ensure_packages systemd-zram-generator

  mkdir -p "$(dirname "$ZRAM_CONF_FILE")"
  if [[ -f "$ZRAM_CONF_FILE" ]]; then
    backup_file "$ZRAM_CONF_FILE"
  fi

  if [[ -n "$ZRAM_ALGO_OVERRIDE" ]]; then
    log_info "Using user-specified ZRAM compression algorithm: $algo"
  else
    log_info "Selected ZRAM compression algorithm: $algo"
  fi

  cat <<CFG > "$ZRAM_CONF_FILE"
[zram0]
zram-size = ${size_mb}M
compression-algorithm = $algo
swap-priority = 100
CFG

  log_info "Configured $ZRAM_CONF_FILE for ${size_mb}MB ZRAM swap"
  systemctl daemon-reload >/dev/null 2>&1 || true
  if systemctl list-unit-files systemd-zram-setup@.service >/dev/null 2>&1; then
    systemctl enable --now systemd-zram-setup@zram0 >/dev/null 2>&1 || log_warn "Unable to enable systemd-zram-setup@zram0"
  else
    log_warn "systemd-zram-setup@.service not found; ensure systemd-zram-generator is installed"
  fi

  write_json_field "$CONFIG_OPTIMISER_STATE" "zram.size_mb" "$size_mb"
  write_json_field "$CONFIG_OPTIMISER_STATE" "zram.algorithm" "$algo"
  write_json_field "$CONFIG_OPTIMISER_STATE" "zram.last_configured" "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"

  if command -v zramctl >/dev/null 2>&1; then
    local zram_status
    zram_status=$(zramctl 2>/dev/null | sed 's/^/    /')
    if [[ -n "$zram_status" ]]; then
      log_info "Current zramctl status:\n$zram_status"
    fi
  fi
  if command -v swapon >/dev/null 2>&1; then
    local swap_status
    swap_status=$(swapon --show 2>/dev/null | sed 's/^/    /')
    if [[ -n "$swap_status" ]]; then
      log_info "Active swap devices:\n$swap_status"
    fi
  fi
}
