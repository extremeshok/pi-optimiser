# ======================================================================
# lib/util/cmdline.sh — /boot/firmware/cmdline.txt helpers
#
# Functions: cmdline_ensure_token
# Globals (read): CMDLINE_FILE
# ======================================================================

# Append a token (e.g. consoleblank=0) to the single cmdline.txt line.
# Returns 0 if the token was appended, 1 if already present, 2 on error.
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
  if grep -qw "$token" "$file"; then
    return 1
  fi
  CMDLINE_PATH="$file" CMDLINE_TOKEN="$token" run_python <<'PY' || return 2
import os
from pathlib import Path
path = Path(os.environ['CMDLINE_PATH'])
token = os.environ['CMDLINE_TOKEN']
content = path.read_text().strip()
parts = content.split()
if token not in parts:
    parts.append(token)
    path.write_text(" ".join(parts) + "\n")
PY
  return 0
}
