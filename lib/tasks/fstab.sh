# >>> pi-task
# id: fstab
# version: 1.2.0
# description: Reduce SD-card wear by tuning root filesystem mount options
# category: storage
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register fstab \
  description="Reduce SD-card wear by tuning root filesystem mount options" \
  category=storage \
  version=1.2.0 \
  default_enabled=1

run_fstab() {
  if grep -E "^[[:space:]]*[^#[:space:]]+[[:space:]]+/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]*noatime" /etc/fstab >/dev/null; then
    log_info "Root filesystem already has noatime configured"
  else
    backup_file /etc/fstab
    run_python <<'PY'
import os
from pathlib import Path
path = Path('/etc/fstab')
# Normalise any CR so a CRLF-ish fstab doesn't gain mixed endings.
raw = path.read_text().replace('\r\n', '\n').replace('\r', '\n')
lines = raw.splitlines()
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
    # Atomic write: a half-written /etc/fstab can make the system
    # unbootable. Stage to .tmp, fsync, then os.replace().
    payload = "\n".join(updated_lines) + "\n"
    tmp = path.with_suffix(path.suffix + '.pi-optimiser.tmp')
    with open(tmp, 'w') as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    try:
        st = path.stat()
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o7777)
    except FileNotFoundError:
        os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    try:
        dfd = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
PY
    log_info "Applied noatime and commit=60 to root filesystem"
    remount_path /
  fi
}
