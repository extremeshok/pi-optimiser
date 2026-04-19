# >>> pi-task
# id: eeprom_config
# version: 1.2.0
# description: Tune Raspberry Pi EEPROM SDRAM_BANKLOW for Pi 4/400/5/500
# category: firmware-eeprom
# default_enabled: 1
# power_sensitive: 1
# <<< pi-task

pi_task_register eeprom_config \
  description="Tune Raspberry Pi EEPROM SDRAM_BANKLOW for Pi 4/400/5/500" \
  category=firmware-eeprom \
  version=1.2.0 \
  default_enabled=1 \
  power_sensitive=1

run_eeprom_config() {
  if ! command -v rpi-eeprom-config >/dev/null 2>&1; then
    log_info "rpi-eeprom-config not available; skipping EEPROM tuning"
    pi_skip_reason "rpi-eeprom-config missing"
    return 2
  fi

  local bank_value=""
  local profile=""
  if is_pi5; then
    bank_value=1
    profile="pi5"
  elif is_pi400; then
    bank_value=3
    profile="pi400"
  elif is_pi4; then
    bank_value=3
    profile="pi4"
  else
    log_info "EEPROM SDRAM tuning not applicable for model ${SYSTEM_MODEL:-unknown}"
    pi_skip_reason "model unsupported"
    return 2
  fi

  mkdir -p "$EEPROM_STAGING_DIR"
  chmod 755 "$EEPROM_STAGING_DIR"

  local current_conf new_conf
  current_conf=$(mktemp)
  new_conf=$(mktemp)
  # Clean up temp files on any exit path — even Python exceptions or
  # mid-function returns — so /tmp/tmp.* doesn't leak.
  # shellcheck disable=SC2064
  trap "rm -f '$current_conf' '$new_conf'" RETURN

  if ! rpi-eeprom-config > "$current_conf" 2>/dev/null; then
    log_warn "Unable to read current EEPROM configuration"
    pi_skip_reason "could not read eeprom config"
    return 2
  fi

  CONF_IN="$current_conf" CONF_OUT="$new_conf" BANK_VALUE="$bank_value" run_python <<'PY'
import os
from pathlib import Path

src = Path(os.environ['CONF_IN'])
dst = Path(os.environ['CONF_OUT'])
bank_value = os.environ['BANK_VALUE']

lines = src.read_text().splitlines() if src.exists() else []
out = []
found = False
for line in lines:
    candidate = line.strip().lstrip('#').strip()
    if candidate.upper().startswith('SDRAM_BANKLOW='):
        if not found:
            out.append(f"SDRAM_BANKLOW={bank_value}")
            found = True
        continue
    out.append(line)
if not found:
    out.append(f"SDRAM_BANKLOW={bank_value}")
dst.write_text('\n'.join(out) + '\n')
PY

  cp "$new_conf" "$EEPROM_STAGING_DIR/boot.conf.pending" 2>/dev/null || true

  if diff -q "$current_conf" "$new_conf" >/dev/null 2>&1; then
    log_info "EEPROM config already has SDRAM_BANKLOW=$bank_value"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.sdram_banklow" "$bank_value"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.profile" "$profile"
    return 0
  fi

  local backup_path
  backup_path="$EEPROM_STAGING_DIR/boot.conf.$(date +%Y%m%d%H%M%S).bak"
  cp "$current_conf" "$backup_path" 2>/dev/null || true

  if rpi-eeprom-config --apply "$new_conf" >/dev/null 2>&1; then
    log_info "Applied SDRAM_BANKLOW=$bank_value to EEPROM (profile: $profile); active after reboot"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.sdram_banklow" "$bank_value"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.profile" "$profile"
    return 0
  fi

  log_warn "rpi-eeprom-config --apply failed; EEPROM unchanged (staged config at $EEPROM_STAGING_DIR/boot.conf.pending)"
  return 1
}
