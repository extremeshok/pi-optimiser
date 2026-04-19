# >>> pi-task
# id: libliftoff
# version: 1.1.0
# description: Disable KMS 'liftoff' to avoid compositor display glitches
# category: display
# default_enabled: 1
# power_sensitive: 1
# reboot_required: true
# <<< pi-task

pi_task_register libliftoff \
  description="Disable KMS 'liftoff' to avoid compositor display glitches" \
  category=display \
  version=1.1.0 \
  default_enabled=1 \
  power_sensitive=1 \
  reboot_required=1

run_libliftoff() {
  if ! pi_supports_kms_overlays; then
    log_info "Skipping libliftoff overlay tuning (model ${SYSTEM_MODEL:-unknown} lacks vc4-kms)"
    pi_skip_reason "model unsupported"
    return 2
  fi
  local cfg="$CONFIG_TXT_FILE"
  if [[ ! -f "$cfg" ]]; then
    log_info "config.txt not present; skipping libliftoff tuning"
    return 0
  fi
  if ! grep -qi 'liftoff' "$cfg" && ! grep -qi 'vc4-kms-v3d' "$cfg"; then
    log_info "No vc4-kms liftoff settings detected"
    return 0
  fi
  backup_file "$cfg"
  local result
  result=$(CONFIG_FILE="$cfg" run_python <<'PY'
import os
from pathlib import Path
cfg_path = Path(os.environ['CONFIG_FILE'])
lines = cfg_path.read_text().splitlines()
changed = False
new_lines = []
for line in lines:
    stripped = line.lstrip()
    prefix = line[:len(line) - len(stripped)]
    commented = False
    if stripped.startswith('#'):
        after_hash = stripped[1:].lstrip()
        if after_hash.lower().startswith('dtoverlay'):
            stripped = after_hash
            commented = True
    lower = stripped.lower()
    if lower.startswith('dtoverlay') and ('liftoff' in lower or 'vc4-kms-v3d' in lower):
        try:
            key, value = stripped.split('=', 1)
        except ValueError:
            new_lines.append(prefix + stripped)
            continue
        opts = [opt for opt in value.split(',') if opt]
        cleaned_opts = []
        liftoff_disabled = False
        for opt in opts:
            opt_lower = opt.strip().lower()
            if opt_lower in {'liftoff', 'liftoff=1', 'liftoff=on'}:
                changed = True
                continue
            if opt_lower in {'no-liftoff', 'liftoff=0', 'liftoff=off', 'disable_liftoff=1'}:
                liftoff_disabled = True
            cleaned_opts.append(opt)
        if not liftoff_disabled:
            cleaned_opts.append('no-liftoff')
            liftoff_disabled = True
        new_value = ','.join(cleaned_opts)
        new_line = f"{key}={new_value}"
        if commented or new_line != stripped:
            changed = True
        stripped = new_line
    new_lines.append(prefix + stripped)
if changed:
    cfg_path.write_text('\n'.join(new_lines) + '\n')
print('changed' if changed else 'unchanged')
PY
  )
  result=${result//$'\n'/}
  if [[ $result == "changed" ]]; then
    log_info "Ensured libliftoff is disabled while keeping KMS overlays active"
  else
    log_info "libliftoff settings already optimal"
  fi
}
