# ======================================================================
# lib/util/python.sh — embedded Python helper
#
# Fixes the cross-cutting bug where Python heredocs in other helpers
# silently swallow exceptions. `run_python` runs a script on stdin,
# captures stdout, propagates non-zero exit, and logs stderr.
#
# Usage:
#   result=$(VAR1=x VAR2=y run_python <<'PY'
#   ...python source reading os.environ...
#   PY
#   )
#   # $? is 0 on success, non-zero on Python exception.
#
# Functions: run_python
# ======================================================================

# Run embedded Python from stdin. Propagates non-zero exit codes and
# forwards stderr to the log. Stdout is returned to the caller.
run_python() {
  local rc=0
  local stderr_file
  stderr_file=$(mktemp)
  # Clean up on any return path — a shell-level signal arriving between
  # the python3 call and the explicit rm -f would otherwise leak
  # /tmp/tmp.XXXXX. RETURN fires on every exit, including error.
  # shellcheck disable=SC2064
  trap "rm -f '$stderr_file'" RETURN
  python3 - 2>"$stderr_file" || rc=$?
  if [[ $rc -ne 0 && -s "$stderr_file" ]]; then
    while IFS= read -r line; do
      log_warn "python: $line"
    done <"$stderr_file"
  fi
  rm -f "$stderr_file"
  return $rc
}

# Atomic file writer: read stdin into a staging file, then have Python
# os.replace() it into place after fsync + parent-dir fsync. Use this
# anywhere a plain `cat > /etc/foo` would otherwise risk leaving a
# half-written system file on power loss — which is alarmingly easy
# to hit on a Pi.
#
# Usage:
#   _pi_atomic_write /etc/foo/bar.conf <<'CFG'
#   key = value
#   CFG
# Preserves existing mode if present, otherwise writes 0644. stdin is
# captured to a tempfile so the inner python3 heredoc doesn't have to
# contend for it (run_python already uses python3's stdin for the
# script body, so we can't also stream payload there).
_pi_atomic_write() {
  local target=$1
  if [[ -z "$target" ]]; then
    return 2
  fi
  local payload_file
  payload_file=$(mktemp) || return 2
  # shellcheck disable=SC2064
  trap "rm -f '$payload_file'" RETURN
  cat >"$payload_file" || return 2
  PI_ATOMIC_TARGET="$target" PI_ATOMIC_PAYLOAD="$payload_file" run_python <<'PY'
import os
from pathlib import Path
target = Path(os.environ['PI_ATOMIC_TARGET'])
payload_file = os.environ['PI_ATOMIC_PAYLOAD']
target.parent.mkdir(parents=True, exist_ok=True)
with open(payload_file, 'rb') as fh:
    payload = fh.read()
tmp = target.with_suffix(target.suffix + '.pi-optimiser.tmp')
with open(tmp, 'wb') as fh:
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())
try:
    st = target.stat()
    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o7777)
except FileNotFoundError:
    os.chmod(tmp, 0o644)
os.replace(tmp, target)
try:
    dfd = os.open(str(target.parent), os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
except OSError:
    pass
PY
}
