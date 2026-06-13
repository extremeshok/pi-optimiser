# ======================================================================
# lib/util/cmdline.sh — /boot/firmware/cmdline.txt helpers
#
# Functions: cmdline_ensure_token, cmdline_get_value, cmdline_set_kv
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

# Print the value of the first `key=value` token on the cmdline.txt line.
# Returns 0 and prints the value (possibly empty) if the key is present;
# returns 1 (prints nothing) if absent. Used to read single-valued kernel
# module params (e.g. usb-storage.quirks) so callers can merge rather
# than blindly append a duplicate token.
cmdline_get_value() {
  local key=$1
  local file=${2:-$CMDLINE_FILE}
  [[ -f "$file" ]] || return 1
  CMDLINE_PATH="$file" CMDLINE_KEY="$key" run_python <<'PY'
import os
from pathlib import Path
path = Path(os.environ['CMDLINE_PATH'])
key = os.environ['CMDLINE_KEY']
try:
    first = path.read_text().replace('\r\n', '\n').replace('\r', '\n').split('\n', 1)[0]
except FileNotFoundError:
    raise SystemExit(1)
for tok in first.split():
    if tok.startswith(key + '='):
        print(tok[len(key) + 1:])
        raise SystemExit(0)
raise SystemExit(1)
PY
}

# Set `key=value` as a SINGLE token in cmdline.txt, replacing any existing
# token for that key in place (and dropping duplicates) rather than
# appending a second one. Kernel module params like usb-storage.quirks
# are single-valued — the parser keeps only the last occurrence — so a
# blind append silently discards an earlier setting. Returns 0 if the
# line changed, 1 if it already matched, 2 on error.
cmdline_set_kv() {
  local key=$1
  local value=$2
  local file=${3:-$CMDLINE_FILE}
  file=$(_pi_config_preview_target "$file") || return 2
  if [[ ! -f "$file" ]]; then
    return 2
  fi
  local result=""
  local rc=0
  result=$(CMDLINE_PATH="$file" CMDLINE_KEY="$key" CMDLINE_VALUE="$value" run_python <<'PY'
import os
from pathlib import Path
path = Path(os.environ['CMDLINE_PATH'])
key = os.environ['CMDLINE_KEY']
value = os.environ['CMDLINE_VALUE'].replace('\r', '').replace('\n', '').strip()
new_token = key + '=' + value
raw = path.read_text()
first_line = raw.replace('\r\n', '\n').replace('\r', '\n').split('\n', 1)[0]
parts = first_line.split()
out = []
replaced = False
changed = False
for tok in parts:
    if tok == key or tok.startswith(key + '='):
        if not replaced:
            out.append(new_token)
            replaced = True
            if tok != new_token:
                changed = True
        else:
            # second/third token for the same key — drop the duplicate
            changed = True
        continue
    out.append(tok)
if not replaced:
    out.append(new_token)
    changed = True
if not changed:
    print('unchanged')
    raise SystemExit(0)
payload = " ".join(out) + "\n"
# Atomic write — cmdline.txt is boot-critical; never leave it truncated.
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
