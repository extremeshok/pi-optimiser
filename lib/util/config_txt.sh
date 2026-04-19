# ======================================================================
# lib/util/config_txt.sh — /boot/firmware/config.txt editors
#
# Functions: ensure_config_line, ensure_config_key_value,
#            ensure_line_in_file, _pi_config_preview_target
# Globals (read): CONFIG_TXT_FILE, PI_CONFIG_PREVIEW, PI_CONFIG_PREVIEW_DIR
#
# Return codes (ensure_config_*):
#   0 — changed
#   1 — unchanged (no-op, not an error)
#   2 — parse/IO failure
# ======================================================================

# Under --diff, helpers divert writes to a scratch buffer so the real
# /boot/firmware/* files are never touched. The buffer is seeded on
# first use from the real file so chained edits compound correctly.
# lib/features/diff.sh::pi_diff_flush prints unified diffs at end-of-run.
_pi_config_preview_target() {
  local real=$1
  if [[ "${PI_CONFIG_PREVIEW:-0}" != "1" ]]; then
    printf '%s\n' "$real"
    return 0
  fi
  if [[ -z "${PI_CONFIG_PREVIEW_DIR:-}" ]]; then
    PI_CONFIG_PREVIEW_DIR=$(mktemp -d /tmp/pi-optimiser-diff.XXXXXX) || return 1
    export PI_CONFIG_PREVIEW_DIR
  fi
  local slug
  slug=$(printf '%s' "$real" | tr '/ .' '___')
  local buf="$PI_CONFIG_PREVIEW_DIR/$slug"
  if [[ ! -f "$buf" ]]; then
    if [[ -f "$real" ]]; then
      cp "$real" "$buf"
    else
      : > "$buf"
    fi
    printf '%s\n' "$real" > "$buf.path"
  fi
  printf '%s\n' "$buf"
}

# Ensure a config.txt line exists exactly once (case-insensitive compare).
ensure_config_line() {
  local line=$1
  local target=${2:-$CONFIG_TXT_FILE}
  if [[ -z "$target" ]]; then
    target=$CONFIG_TXT_FILE
  fi
  target=$(_pi_config_preview_target "$target") || return 2
  if [[ ! -f "$target" ]]; then
    touch "$target"
  fi
  local result=""
  local rc=0
  result=$(CONFIG_FILE="$target" CONFIG_LINE="$line" run_python <<'PY'
import os, sys
from pathlib import Path
config_path = Path(os.environ['CONFIG_FILE'])
line = os.environ['CONFIG_LINE'].strip()
try:
    existing = config_path.read_text().splitlines()
except FileNotFoundError:
    existing = []
out_lines = []
line_lower = line.lower()
changed = False
found = False
for raw in existing:
    stripped = raw.strip()
    candidate = stripped.lstrip('#').strip().lower()
    if candidate == line_lower:
        if not found:
            if stripped != line:
                changed = True
            out_lines.append(line)
            found = True
        else:
            changed = True
        continue
    out_lines.append(raw)
if not found:
    out_lines.append(line)
    changed = True
config_path.write_text('\n'.join(out_lines) + '\n')
print('changed' if changed else 'unchanged')
PY
  ) || rc=$?
  if [[ $rc -ne 0 ]]; then
    return 2
  fi
  if [[ $result == "changed" ]]; then
    return 0
  fi
  return 1
}

# Ensure config.txt contains exactly one `key=value` line for the given key.
# Replaces any previous value (commented or not) for the same key.
ensure_config_key_value() {
  local entry=$1
  local target=${2:-$CONFIG_TXT_FILE}
  if [[ -z "$target" ]]; then
    target=$CONFIG_TXT_FILE
  fi
  if [[ "$entry" != *=* ]]; then
    return 2
  fi
  target=$(_pi_config_preview_target "$target") || return 2
  if [[ ! -f "$target" ]]; then
    touch "$target"
  fi
  local key=${entry%%=*}
  local result=""
  local rc=0
  result=$(CONFIG_FILE="$target" CONFIG_ENTRY="$entry" CONFIG_KEY="$key" run_python <<'PY'
import os
from pathlib import Path
config_path = Path(os.environ['CONFIG_FILE'])
entry = os.environ['CONFIG_ENTRY'].strip()
key = os.environ['CONFIG_KEY'].strip().lower()
try:
    existing = config_path.read_text().splitlines()
except FileNotFoundError:
    existing = []
out_lines = []
changed = False
found = False
for raw in existing:
    stripped = raw.strip()
    candidate = stripped.lstrip('#').strip()
    if '=' in candidate:
        cand_key = candidate.split('=', 1)[0].strip().lower()
        if cand_key == key:
            if not found:
                if stripped != entry:
                    changed = True
                out_lines.append(entry)
                found = True
            else:
                changed = True
            continue
    out_lines.append(raw)
if not found:
    out_lines.append(entry)
    changed = True
config_path.write_text('\n'.join(out_lines) + '\n')
print('changed' if changed else 'unchanged')
PY
  ) || rc=$?
  if [[ $rc -ne 0 ]]; then
    return 2
  fi
  if [[ $result == "changed" ]]; then
    return 0
  fi
  return 1
}

