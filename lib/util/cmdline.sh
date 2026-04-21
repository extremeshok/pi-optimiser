# ======================================================================
# lib/util/cmdline.sh — /boot/firmware/cmdline.txt helpers
#
# Functions: cmdline_ensure_token
# Globals (read): CMDLINE_FILE
# ======================================================================

# Append a token (e.g. consoleblank=0) to the single cmdline.txt line.
# Returns 0 if the token was appended, 1 if already present, 2 on error.
#
# cmdline.txt MUST remain a single line — the firmware parser reads only
# the first line, so any helper that inserts \n breaks boot. We delegate
# the match + rewrite to Python so we can do an exact-token compare
# (grep -w treats `=` / `.` / `-` as word characters on some builds, so
# `arm_boost=1` would falsely match `arm_boost=0`).
cmdline_ensure_token() {
  local token=$1
  local file=${2:-$CMDLINE_FILE}
  # Divert writes to a scratch buffer under --diff so /boot/firmware/
  # stays untouched; the buffer is seeded with the current file so
  # chained edits compound. See lib/util/config_txt.sh for the helper.
  file=$(_pi_config_preview_target "$file") || return 2
  if [[ ! -f "$file" ]]; then
    return 2
  fi
  local result=""
  local rc=0
  result=$(CMDLINE_PATH="$file" CMDLINE_TOKEN="$token" run_python <<'PY'
import os
from pathlib import Path
path = Path(os.environ['CMDLINE_PATH'])
# Strip any stray CR/LF from the caller-supplied token so we cannot
# introduce a newline into cmdline.txt under any circumstance.
token = os.environ['CMDLINE_TOKEN'].replace('\r', '').replace('\n', '').strip()
if not token:
    print('unchanged')
    raise SystemExit(0)
raw = path.read_text()
# Normalise any CRLF / extra lines the user may have introduced down
# to a single line of whitespace-delimited tokens.
first_line = raw.replace('\r\n', '\n').replace('\r', '\n').split('\n', 1)[0]
parts = first_line.split()
if token in parts:
    print('unchanged')
    raise SystemExit(0)
parts.append(token)
payload = " ".join(parts) + "\n"
# Atomic write — cmdline.txt is the single most boot-critical file
# here. A truncate-then-write interrupted by power loss leaves the
# Pi with an empty cmdline.txt and an unbootable system.
tmp_path = path.with_suffix(path.suffix + '.pi-optimiser.tmp')
with open(tmp_path, 'w') as fh:
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp_path, path)
try:
    dfd = os.open(str(path.parent), os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
except OSError:
    pass
print('changed')
PY
  ) || rc=$?
  if [[ $rc -ne 0 ]]; then
    return 2
  fi
  if [[ "$result" == "changed" ]]; then
    return 0
  fi
  return 1
}
