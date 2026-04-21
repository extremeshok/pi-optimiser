# ======================================================================
# lib/util/fstab.sh — /etc/fstab helpers
#
# Functions: fstab_append_line, fstab_root_has_option
# ======================================================================

# Return success when /etc/fstab's root entry already declares an option.
# Matches option names as comma-delimited tokens in the 4th mount column.
fstab_root_has_option() {
  local opt=$1
  grep -E "^[[:space:]]*[^#[:space:]]+[[:space:]]+/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]*${opt}([,[:space:]]|$)" /etc/fstab >/dev/null
}

# Append a complete fstab entry if not already present.
# Matches on the MNT (2nd column) to avoid duplicate mountpoints. The
# entry must be a valid 6-field line (fs_spec, mount_point, type,
# options, dump, pass) or we refuse to write it — a malformed fstab
# row can prevent the system from booting on the next reboot.
# Atomically writes via /etc/fstab.pi-optimiser.tmp + rename so a
# power loss mid-edit cannot leave a half-written fstab.
# Returns 0 if appended, 1 if mountpoint already present, 2 on error.
fstab_append_line() {
  local line=$1
  # Strip CR so a caller passing a CRLF-laced entry doesn't inject mixed
  # line endings into /etc/fstab.
  line=${line//$'\r'/}
  # Fail early on multi-line input — we only write a single row at a time.
  case $line in
    *$'\n'*) return 2 ;;
  esac
  # Validate 6-field syntax. awk's NF counts whitespace-separated fields.
  local fields
  fields=$(awk '{print NF}' <<<"$line")
  if [[ "$fields" != "6" ]]; then
    return 2
  fi
  local mount
  mount=$(awk '{print $2}' <<<"$line")
  if [[ -z "$mount" ]]; then
    return 2
  fi
  if grep -E "^[[:space:]]*[^#[:space:]]+[[:space:]]+${mount}[[:space:]]+" /etc/fstab >/dev/null 2>&1; then
    return 1
  fi
  # Atomic append: read current fstab, stage a new one with our line
  # tacked on, fsync, then os.replace. A truncate-then-append (echo >>)
  # can leave a half-written last line if power drops; systemd's fstab
  # generator is picky enough that a broken last row prevents boot.
  FSTAB_LINE="$line" run_python <<'PY' || return 2
import os
from pathlib import Path
path = Path('/etc/fstab')
line = os.environ['FSTAB_LINE']
current = path.read_text() if path.exists() else ''
if current and not current.endswith('\n'):
    current += '\n'
payload = current + line + '\n'
tmp = path.with_suffix(path.suffix + '.pi-optimiser.tmp')
with open(tmp, 'w') as fh:
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())
# Preserve ownership/mode of the original (root:root 0644 typically).
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
  return 0
}
