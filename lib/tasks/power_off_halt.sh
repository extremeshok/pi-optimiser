# >>> pi-task
# id: power_off_halt
# version: 1.0.0
# description: Cut idle power to ~0.01 W after shutdown (POWER_OFF_ON_HALT=1)
# category: firmware-eeprom
# default_enabled: 0
# power_sensitive: 0
# flags: --power-off-halt
# gate_var: POWER_OFF_HALT
# reboot_required: true
# <<< pi-task

pi_task_register power_off_halt \
  description="Cut idle power to ~0.01 W after shutdown (POWER_OFF_ON_HALT=1)" \
  category=firmware-eeprom \
  version=1.0.0 \
  default_enabled=0 \
  flags="--power-off-halt" \
  gate_var=POWER_OFF_HALT \
  reboot_required=1

# Applies the Pi 5 EEPROM tweak that cuts the 3V3 rail when the Pi is
# powered off, dropping idle current from ~1.2 W to ~0.01 W. Caveat:
# some HATs use the 3V3 rail to keep a coprocessor alive (e.g. RTCs
# with battery backup, certain PoE HATs). The operator opts in with
# `--power-off-halt` if they're sure no HAT relies on that rail.
#
# Credit: Jeff Geerling surfaced this setting in 2024.
#   https://www.jeffgeerling.com/blog/2024/ (vampire-power tip)
run_power_off_halt() {
  if [[ ${POWER_OFF_HALT:-0} -eq 0 ]]; then
    log_info "POWER_OFF_ON_HALT not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if ! is_pi5; then
    log_info "POWER_OFF_ON_HALT only applies to Pi 5/500; skipping"
    pi_skip_reason "model unsupported"
    return 2
  fi
  if ! command -v rpi-eeprom-config >/dev/null 2>&1; then
    log_warn "rpi-eeprom-config not available; cannot set POWER_OFF_ON_HALT"
    pi_skip_reason "rpi-eeprom-config missing"
    return 2
  fi

  mkdir -p "$EEPROM_STAGING_DIR"
  chmod 700 "$EEPROM_STAGING_DIR"

  local current_conf new_conf
  current_conf=$(mktemp)
  new_conf=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f '$current_conf' '$new_conf'" RETURN

  if ! rpi-eeprom-config > "$current_conf" 2>/dev/null; then
    log_warn "Unable to read current EEPROM configuration"
    pi_skip_reason "could not read eeprom config"
    return 2
  fi

  CONF_IN="$current_conf" CONF_OUT="$new_conf" run_python <<'PY'
import os
from pathlib import Path
src = Path(os.environ['CONF_IN'])
dst = Path(os.environ['CONF_OUT'])
lines = src.read_text().splitlines() if src.exists() else []
out = []
found = False
for line in lines:
    candidate = line.strip().lstrip('#').strip()
    if candidate.upper().startswith('POWER_OFF_ON_HALT='):
        if not found:
            out.append("POWER_OFF_ON_HALT=1")
            found = True
        continue
    out.append(line)
if not found:
    out.append("POWER_OFF_ON_HALT=1")
dst.write_text('\n'.join(out) + '\n')
PY

  if diff -q "$current_conf" "$new_conf" >/dev/null 2>&1; then
    log_info "POWER_OFF_ON_HALT=1 already set"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.power_off_on_halt" "1"
    return 0
  fi

  local backup_path
  backup_path="$EEPROM_STAGING_DIR/boot.conf.$(date +%Y%m%d%H%M%S).bak"
  cp "$current_conf" "$backup_path" 2>/dev/null || true
  cp "$new_conf" "$EEPROM_STAGING_DIR/boot.conf.pending" 2>/dev/null || true

  if rpi-eeprom-config --apply "$new_conf" >/dev/null 2>&1; then
    log_info "Applied POWER_OFF_ON_HALT=1 to EEPROM (active after reboot + shutdown cycle)"
    log_info "Warning: 3V3 rail cuts on halt — detach any HAT that needs 3V3 while powered off"
    write_json_field "$CONFIG_OPTIMISER_STATE" "eeprom.power_off_on_halt" "1"
    return 0
  fi
  log_warn "rpi-eeprom-config --apply failed (pending config at $EEPROM_STAGING_DIR/boot.conf.pending)"
  return 1
}
