# >>> pi-task
# id: fstab
# version: 1.1.0
# description: Reduce SD-card wear by tuning root filesystem mount options
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register fstab \
  description="Reduce SD-card wear by tuning root filesystem mount options" \
  category=storage \
  version=1.1.0 \
  default_enabled=1

run_fstab() {
  if grep -E "^[[:space:]]*[^#[:space:]]+[[:space:]]+/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]*noatime" /etc/fstab >/dev/null; then
    log_info "Root filesystem already has noatime configured"
  else
    backup_file /etc/fstab
    run_python <<'PY'
from pathlib import Path
path = Path('/etc/fstab')
lines = path.read_text().splitlines()
updated_lines = []
changed = False
for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        updated_lines.append(line)
        continue
    parts = line.split()
    if len(parts) >= 4 and parts[1] == '/':
        opts = parts[3].split(',')
        ordered = []
        seen = set()
        for opt in opts:
            if opt and opt not in seen:
                ordered.append(opt)
                seen.add(opt)
        desired = ['noatime', 'commit=60', 'errors=remount-ro']
        for opt in desired:
            if opt not in seen:
                ordered.append(opt)
                seen.add(opt)
                changed = True
        parts[3] = ','.join(ordered)
        line = "\t".join(parts[:4])
        if len(parts) > 4:
            line = line + "\t" + "\t".join(parts[4:])
    updated_lines.append(line)
if changed:
    path.write_text("\n".join(updated_lines) + "\n")
PY
    log_info "Applied noatime and commit=60 to root filesystem"
    remount_path /
  fi
}
