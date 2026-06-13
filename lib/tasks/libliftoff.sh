# >>> pi-task
# id: libliftoff
# version: 1.2.0
# description: Disable KMS 'liftoff' to avoid compositor display glitches
# category: display
# default_enabled: 1
# power_sensitive: 1
# reboot_required: true
# <<< pi-task

pi_task_register libliftoff \
  description="Disable KMS 'liftoff' to avoid compositor display glitches" \
  category=display \
  version=1.2.0 \
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
    pi_skip_reason "config.txt missing"
    return 2
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

def is_kms_overlay(stripped_lower):
    # Only ACTIVE dtoverlay lines for the KMS driver (or any line that
    # explicitly mentions liftoff). Commented lines are deliberately
    # left alone — a `#dtoverlay=vc4-kms-v3d` is the operator opting OUT,
    # and uncommenting it would activate KMS against their wishes.
    return stripped_lower.startswith('dtoverlay') and (
        'vc4-kms-v3d' in stripped_lower or 'liftoff' in stripped_lower)

# Collect the merged option set across EVERY active KMS overlay line and
# remember the first such position. boot_config (which runs earlier and
# writes a bare `dtoverlay=vc4-kms-v3d`) can leave a duplicate alongside
# the one we previously rewrote to `,no-liftoff`; collapsing them here to
# a single canonical line prevents the duplicate accumulating on re-runs.
first_idx = None
merged = []
seen = set()
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith('#'):
        continue
    if not is_kms_overlay(stripped.lower()) or '=' not in stripped:
        continue
    if first_idx is None:
        first_idx = i
    for opt in stripped.split('=', 1)[1].split(','):
        opt = opt.strip()
        if opt and opt.lower() not in seen:
            seen.add(opt.lower())
            merged.append(opt)

out = []
if first_idx is not None:
    # Drop any liftoff-enable token; guarantee exactly one no-liftoff.
    cleaned = []
    has_no_liftoff = False
    for opt in merged:
        ol = opt.lower()
        if ol in {'liftoff', 'liftoff=1', 'liftoff=on'}:
            continue
        if ol in {'no-liftoff', 'liftoff=0', 'liftoff=off', 'disable_liftoff=1'}:
            has_no_liftoff = True
        cleaned.append(opt)
    if not has_no_liftoff:
        cleaned.append('no-liftoff')
    canonical = 'dtoverlay=' + ','.join(cleaned)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith('#') and is_kms_overlay(stripped.lower()) and '=' in stripped:
            if i == first_idx:
                prefix = line[:len(line) - len(line.lstrip())]
                if (prefix + canonical) != line:
                    changed = True
                out.append(prefix + canonical)
            else:
                # duplicate active KMS overlay line — drop it
                changed = True
            continue
        out.append(line)
else:
    out = lines

if changed:
    cfg_path.write_text('\n'.join(out) + '\n')
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
