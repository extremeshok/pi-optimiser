# >>> pi-task
# id: hostname
# version: 1.1.0
# description: Set system hostname when --hostname is provided
# category: system
# default_enabled: 0
# power_sensitive: 0
# flags: --hostname
# gate_var: REQUESTED_HOSTNAME
# <<< pi-task

pi_task_register hostname \
  description="Set system hostname when --hostname is provided" \
  category=system \
  version=1.1.0 \
  default_enabled=0 \
  flags="--hostname" \
  gate_var=REQUESTED_HOSTNAME

run_hostname() {
  if [[ -z "$REQUESTED_HOSTNAME" ]]; then
    log_info "No hostname requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  if ! [[ $REQUESTED_HOSTNAME =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
    log_error "Invalid hostname '$REQUESTED_HOSTNAME' (must be RFC 1123 label)"
    return 1
  fi
  local old_hostname
  old_hostname=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "raspberrypi")
  if command -v hostnamectl >/dev/null 2>&1; then
    hostnamectl set-hostname "$REQUESTED_HOSTNAME"
  else
    echo "$REQUESTED_HOSTNAME" > /etc/hostname
    hostname "$REQUESTED_HOSTNAME" >/dev/null 2>&1 || true
  fi
  if [[ -f /etc/hosts ]]; then
    backup_file /etc/hosts
    OLD_HN="$old_hostname" NEW_HN="$REQUESTED_HOSTNAME" run_python <<'PY'
import os
from pathlib import Path
path = Path('/etc/hosts')
old = os.environ['OLD_HN']
new = os.environ['NEW_HN']
lines = path.read_text().splitlines()
out = []
for line in lines:
    stripped = line.strip()
    if stripped.startswith('127.0.1.1'):
        parts = line.split()
        if len(parts) >= 2:
            parts = [parts[0], new] + [p for p in parts[2:] if p != old]
            out.append('\t'.join(parts))
            continue
    out.append(line)
have_127_0_1_1 = any(l.strip().startswith('127.0.1.1') for l in out)
if not have_127_0_1_1:
    out.append(f"127.0.1.1\t{new}")
path.write_text('\n'.join(out) + '\n')
PY
  fi
  log_info "System hostname set to $REQUESTED_HOSTNAME"
  write_json_field "$CONFIG_OPTIMISER_STATE" "hostname.name" "$REQUESTED_HOSTNAME"
}
