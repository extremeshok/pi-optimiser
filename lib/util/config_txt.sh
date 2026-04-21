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
#
# Section-aware editing (9.3.1+):
#   Pi firmware config.txt uses conditional sections: [all], [pi5],
#   [pi4], [pi3], [pi02], [cm4], [none], etc. A setting written inside
#   [none] applies to no model and is silently ignored — a blind
#   end-of-file append into a user's file ending `[none]` would drop
#   our setting on the floor.
#
#   ensure_config_line / ensure_config_key_value take an OPTIONAL third
#   arg `section` (default `all`). The Python logic parses the file
#   into sections and edits/creates within the requested one:
#
#     - If the section exists, the entry is upserted inside it.
#     - If the section is absent, it is created immediately BEFORE the
#       final `[none]` block (so our new section is the effective one
#       at boot) or at end-of-file if no `[none]` trails.
#     - Idempotency: if the same key already has a value inside the
#       requested section, it is updated in-place. If it exists in a
#       DIFFERENT section, we leave that line alone and add a new
#       entry in the requested section; a WARN is emitted so the
#       operator sees the potential conflict.
#     - Atomic write is preserved (stage .tmp + os.replace + fsync).
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

# Ensure a config.txt line exists exactly once inside a given section.
# Args: 1=line, 2=target (default $CONFIG_TXT_FILE), 3=section (default all).
ensure_config_line() {
  local line=$1
  local target=${2:-$CONFIG_TXT_FILE}
  local section=${3:-all}
  if [[ -z "$target" ]]; then
    target=$CONFIG_TXT_FILE
  fi
  target=$(_pi_config_preview_target "$target") || return 2
  if [[ ! -f "$target" ]]; then
    touch "$target"
  fi
  # Sidecar file for WARN messages. run_python only surfaces stderr
  # on non-zero exit, so cross-section conflict warnings would be
  # silently dropped on a successful write. Python appends to this
  # file; we read it back and emit via log_warn after the call.
  local warn_file
  warn_file=$(mktemp) || return 2
  local result=""
  local rc=0
  result=$(CONFIG_FILE="$target" CONFIG_LINE="$line" CONFIG_SECTION="$section" \
    CONFIG_MODE="line" CONFIG_WARN_FILE="$warn_file" run_python <<'PY'
import os
from pathlib import Path

config_path = Path(os.environ['CONFIG_FILE'])
warn_path = os.environ.get('CONFIG_WARN_FILE', '')
# Strip CR from caller-supplied line to keep LF-only output on disk.
line = os.environ['CONFIG_LINE'].strip().replace('\r', '')
target_section = os.environ['CONFIG_SECTION'].strip().lower() or 'all'

def _warn(msg):
    if warn_path:
        with open(warn_path, 'a') as wh:
            wh.write(msg.rstrip('\n') + '\n')

try:
    # Normalise CRLF on read so we never re-emit mixed line endings.
    existing = config_path.read_text().replace('\r\n', '\n').replace('\r', '\n').splitlines()
except FileNotFoundError:
    existing = []

# Parse sections: every `[name]` header on its own line starts a new
# section; lines before the first header belong to the implicit [all]
# preamble.
def parse_sections(lines):
    sections = [('all', [])]  # (name, body_lines) — preamble uses 'all'
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']') and len(stripped) >= 2:
            name = stripped[1:-1].strip().lower()
            sections.append((name, []))
        else:
            sections[-1][1].append(raw)
    return sections

sections = parse_sections(existing)

# If the file starts with section headers (no preamble content), the
# implicit 'all' preamble is empty. That's still a valid 'all'
# section for our purposes — we'll append into it if target is 'all'.

line_lower = line.lower()

# Step 1: scan ALL sections for an existing match so we can detect
# cross-section conflicts.
match_in_target = None     # index in the target section's body
match_foreign_section = None  # a different section that also has the key

for idx, (name, body) in enumerate(sections):
    for i, raw in enumerate(body):
        stripped = raw.strip()
        candidate = stripped.lstrip('#').strip().lower()
        if candidate == line_lower:
            if name == target_section and match_in_target is None:
                match_in_target = (idx, i)
            elif name != target_section and match_foreign_section is None:
                match_foreign_section = name

changed = False

if match_in_target is not None:
    # Update in place inside the target section.
    sec_idx, body_idx = match_in_target
    name, body = sections[sec_idx]
    existing_line = body[body_idx]
    if existing_line.strip() != line:
        body[body_idx] = line
        changed = True
    # Drop any duplicates of the same line within the target section.
    # (Keeps idempotency: second run leaves exactly one copy.)
    seen = False
    new_body = []
    for raw in body:
        if raw.strip().lstrip('#').strip().lower() == line_lower:
            if not seen:
                new_body.append(raw)
                seen = True
            else:
                changed = True
                continue
        else:
            new_body.append(raw)
    sections[sec_idx] = (name, new_body)
else:
    # Not in target section. If another section has it, warn but DO
    # NOT remove it — the operator may have put it there deliberately.
    if match_foreign_section is not None:
        _warn(
            "config_txt: line present in [%s]; also adding to [%s] as requested"
            % (match_foreign_section, target_section)
        )

    # Locate (or create) the target section.
    target_idx = None
    for idx, (name, _body) in enumerate(sections):
        if name == target_section:
            target_idx = idx
            break

    if target_idx is None:
        # Create the section. Insert BEFORE any terminal [none] block
        # so our new section is effective. A terminal [none] is one
        # where no later section would re-activate other models.
        insert_at = len(sections)
        for idx in range(len(sections) - 1, -1, -1):
            if sections[idx][0] == 'none':
                insert_at = idx
            else:
                break
        sections.insert(insert_at, (target_section, [line]))
        changed = True
    else:
        sections[target_idx][1].append(line)
        changed = True

# Serialise. The implicit preamble ('all' at index 0) has no header.
out_lines = []
for idx, (name, body) in enumerate(sections):
    if idx == 0 and name == 'all':
        # preamble — no header emitted unless we explicitly created
        # [all] as a new section at the top (which we don't: we only
        # create sections when the name isn't already in the list).
        out_lines.extend(body)
    else:
        out_lines.append('[%s]' % name)
        out_lines.extend(body)

# Atomic write: stage under .tmp then os.replace() so a power loss
# can never leave /boot/firmware/config.txt truncated. os.replace is
# atomic on POSIX; fsync the file + directory so the rename is
# durable before we return.
payload = '\n'.join(out_lines) + '\n'
tmp_path = config_path.with_suffix(config_path.suffix + '.pi-optimiser.tmp')
with open(tmp_path, 'w') as fh:
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp_path, config_path)
try:
    dfd = os.open(str(config_path.parent), os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
except OSError:
    pass
print('changed' if changed else 'unchanged')
PY
  ) || rc=$?
  # Emit any WARNs the Python side queued (cross-section conflicts,
  # etc.) via log_warn so they surface under --report / --status.
  if [[ -s "$warn_file" ]]; then
    while IFS= read -r _line; do
      [[ -z "$_line" ]] || log_warn "$_line"
    done <"$warn_file"
  fi
  rm -f "$warn_file"
  if [[ $rc -ne 0 ]]; then
    return 2
  fi
  if [[ $result == "changed" ]]; then
    return 0
  fi
  return 1
}

# Ensure config.txt contains exactly one `key=value` line for the given
# key, inside the given section.
# Args: 1=entry (key=value), 2=target (default $CONFIG_TXT_FILE),
#       3=section (default all).
# Replaces any previous value for the same key in the target section;
# warns if the same key exists in a different section.
ensure_config_key_value() {
  local entry=$1
  local target=${2:-$CONFIG_TXT_FILE}
  local section=${3:-all}
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
  local warn_file
  warn_file=$(mktemp) || return 2
  local result=""
  local rc=0
  result=$(CONFIG_FILE="$target" CONFIG_ENTRY="$entry" CONFIG_KEY="$key" \
    CONFIG_SECTION="$section" CONFIG_WARN_FILE="$warn_file" run_python <<'PY'
import os
from pathlib import Path

config_path = Path(os.environ['CONFIG_FILE'])
warn_path = os.environ.get('CONFIG_WARN_FILE', '')
# Strip CR so a caller passing a CRLF-laced value doesn't seed mixed
# line endings into /boot/firmware/config.txt.
entry = os.environ['CONFIG_ENTRY'].strip().replace('\r', '')
key = os.environ['CONFIG_KEY'].strip().lower()
target_section = os.environ['CONFIG_SECTION'].strip().lower() or 'all'

def _warn(msg):
    if warn_path:
        with open(warn_path, 'a') as wh:
            wh.write(msg.rstrip('\n') + '\n')

try:
    existing = config_path.read_text().replace('\r\n', '\n').replace('\r', '\n').splitlines()
except FileNotFoundError:
    existing = []

def parse_sections(lines):
    sections = [('all', [])]
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']') and len(stripped) >= 2:
            name = stripped[1:-1].strip().lower()
            sections.append((name, []))
        else:
            sections[-1][1].append(raw)
    return sections

def is_key_line(raw, want_key):
    stripped = raw.strip()
    candidate = stripped.lstrip('#').strip()
    if '=' not in candidate:
        return False
    cand_key = candidate.split('=', 1)[0].strip().lower()
    return cand_key == want_key

sections = parse_sections(existing)

# Locate matches for this key across sections.
match_in_target = None        # (section_idx, body_idx)
match_foreign_section = None  # first other section name that has the key

for idx, (name, body) in enumerate(sections):
    for i, raw in enumerate(body):
        if is_key_line(raw, key):
            if name == target_section and match_in_target is None:
                match_in_target = (idx, i)
            elif name != target_section and match_foreign_section is None:
                match_foreign_section = name

changed = False

if match_in_target is not None:
    sec_idx, body_idx = match_in_target
    name, body = sections[sec_idx]
    if body[body_idx].strip() != entry:
        body[body_idx] = entry
        changed = True
    # Drop any duplicate copies of the same key within the target
    # section so second-run stays at exactly one.
    seen = False
    new_body = []
    for raw in body:
        if is_key_line(raw, key):
            if not seen:
                new_body.append(raw)
                seen = True
            else:
                changed = True
                continue
        else:
            new_body.append(raw)
    sections[sec_idx] = (name, new_body)
else:
    if match_foreign_section is not None:
        _warn(
            "config_txt: %s already set in [%s]; also writing to [%s] "
            "(foreign section left intact)"
            % (key, match_foreign_section, target_section)
        )

    target_idx = None
    for idx, (name, _body) in enumerate(sections):
        if name == target_section:
            target_idx = idx
            break

    if target_idx is None:
        # Insert new section BEFORE any terminal [none] block.
        insert_at = len(sections)
        for idx in range(len(sections) - 1, -1, -1):
            if sections[idx][0] == 'none':
                insert_at = idx
            else:
                break
        sections.insert(insert_at, (target_section, [entry]))
        changed = True
    else:
        sections[target_idx][1].append(entry)
        changed = True

out_lines = []
for idx, (name, body) in enumerate(sections):
    if idx == 0 and name == 'all':
        out_lines.extend(body)
    else:
        out_lines.append('[%s]' % name)
        out_lines.extend(body)

# Atomic write: stage .tmp + os.replace so a power loss between
# truncate and write can never brick the boot config. Durable via
# file + parent-dir fsync.
payload = '\n'.join(out_lines) + '\n'
tmp_path = config_path.with_suffix(config_path.suffix + '.pi-optimiser.tmp')
with open(tmp_path, 'w') as fh:
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp_path, config_path)
try:
    dfd = os.open(str(config_path.parent), os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
except OSError:
    pass
print('changed' if changed else 'unchanged')
PY
  ) || rc=$?
  if [[ -s "$warn_file" ]]; then
    while IFS= read -r _line; do
      [[ -z "$_line" ]] || log_warn "$_line"
    done <"$warn_file"
  fi
  rm -f "$warn_file"
  if [[ $rc -ne 0 ]]; then
    return 2
  fi
  if [[ $result == "changed" ]]; then
    return 0
  fi
  return 1
}

