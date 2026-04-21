# ======================================================================
# lib/util/backup.sh — timestamped file backups with rotation + journal
#
# Functions: backup_file, record_created, prune_backups
# Globals (read):  BACKED_UP, BACKUP_KEEP_COUNT, CURRENT_TASK,
#                  MARKER_DIR
#
# For every `.pi-optimiser.<ts>` backup produced, we append a JSON
# record to $MARKER_DIR/backups/<task>.json so `--undo <task>` can
# locate what to restore. The journal is append-only within a run —
# the first backup for a (task,original_path) pair wins, further
# edits of the same file are *not* re-logged (matches BACKED_UP).
#
# For NEW files that tasks create from scratch (systemd units, apt
# repo lists, drop-ins), there's no original to back up — instead we
# record the path with `created: true` so `--undo` removes the file
# rather than trying to restore a non-existent original. Callers use
# `record_created <path>` BEFORE writing the file; if a prior edit
# record already exists for the same path we leave it alone (the
# pre-existing version wins and --undo restores it).
# ======================================================================

# Keep the pristine (oldest) plus the N-1 most recent .pi-optimiser.*
# backups for each backed-up path. Defaults to 5 if BACKUP_KEEP_COUNT
# is unset.
#
# The oldest backup is the pristine copy (taken on the first run
# against that path) and is preserved so --undo can always return the
# system to its factory state, even after many re-runs.
prune_backups() {
  local path=$1
  local keep=${BACKUP_KEEP_COUNT:-5}
  if (( keep <= 0 )); then
    return 0
  fi
  local parent base
  parent=$(dirname "$path")
  base=$(basename "$path")
  local -a backups=()
  local entry
  # Include symlinks too — cp -a preserves link semantics and we
  # shouldn't treat a symlink backup differently for rotation.
  while IFS= read -r entry; do
    [[ -n "$entry" ]] && backups+=("$entry")
  done < <(find "$parent" -maxdepth 1 \( -type f -o -type l \) \
              -name "${base}.pi-optimiser.*" 2>/dev/null | sort)
  local total=${#backups[@]}
  if (( total <= keep )); then
    return 0
  fi
  # Drop the middle entries, keeping index 0 (pristine) + the newest keep-1.
  local drop=$(( total - keep ))
  local i
  for (( i=1; i<=drop; i++ )); do
    rm -f "${backups[i]}" 2>/dev/null || true
  done
}

# Copy original file to timestamped backup once per run, log the pairing
# into the current task's journal, and prune old backups.
#
# Preserves mode + ownership via `cp -a` so --undo can re-establish the
# original permissions. Symlinks are preserved as symlinks (cp -a keeps
# the link itself rather than dereferencing the target).
#
# Idempotency: if a pristine backup for this path already exists on disk
# from a previous run, we do NOT overwrite it with the current (possibly
# already-mutated) content. A fresh per-run copy is created only when no
# prior .pi-optimiser.* backup exists, which preserves the original file
# across repeated task runs.
backup_file() {
  local path=$1
  # Use -e so we capture symlinks too (a broken symlink still counts as
  # something the operator may want to restore). Skip if the path is
  # neither a regular file nor a symlink (device nodes, directories).
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    return
  fi
  if [[ -L "$path" ]]; then
    : # symlink — handled below via cp -a
  elif [[ ! -f "$path" ]]; then
    return
  fi
  if [[ -n ${BACKED_UP[$path]:-} ]]; then
    return
  fi
  local backup parent base existing=""
  parent=$(dirname "$path")
  base=$(basename "$path")
  # Reuse the oldest existing backup as the pristine copy so repeated
  # runs don't overwrite the original with already-mutated content.
  if [[ -d "$parent" ]]; then
    existing=$(find "$parent" -maxdepth 1 \( -type f -o -type l \) \
                 -name "${base}.pi-optimiser.*" 2>/dev/null | sort | head -n1)
  fi
  if [[ -n "$existing" ]]; then
    backup=$existing
    log_info "Reusing existing backup $backup (pristine preserved)"
  else
    backup="${path}.pi-optimiser.$(date +%Y%m%d%H%M%S)"
    # cp -a preserves mode, ownership, timestamps, and symlinks.
    cp -a "$path" "$backup"
    log_info "Created backup $backup"
  fi
  BACKED_UP["$path"]="$backup"
  prune_backups "$path"
  _backup_journal_append "$path" "$backup"
}

# Register a newly-created file in the current task's journal so `--undo`
# can remove it on revert. Call this BEFORE writing the file — if the
# path already exists we fall back to backup_file (the pre-existing
# version becomes the restore target and --undo puts it back instead
# of deleting).
#
# Idempotent: if a journal entry for this path already exists in the
# current run (create or edit), we don't overwrite it. BACKED_UP is
# updated so backup_file() later in the same task is a no-op.
record_created() {
  local path=$1
  [[ -z "$path" ]] && return 0
  # Pre-existing file — treat as an edit so the original content is
  # preserved across --undo. The new write that follows will trigger
  # the usual edit path via backup_file + task write.
  if [[ -e "$path" || -L "$path" ]]; then
    backup_file "$path"
    return 0
  fi
  if [[ -n ${BACKED_UP[$path]:-} ]]; then
    return 0
  fi
  # Sentinel value distinguishes "created" from "edited". undo.sh keys
  # off the journal entry's `created` field; BACKED_UP is only used
  # locally to suppress duplicate registration within a run.
  BACKED_UP["$path"]="__CREATED__"
  _backup_journal_record_created "$path"
}

# Per-run NDJSON scratch buffers for the backup journal.
#
# The journal writer used to invoke Python (~100ms startup on a Pi)
# once per backed-up file. A run backing up 30 files cost ~3s just in
# interpreter startup, on top of reading+rewriting the full JSON each
# time (O(N^2) over a run).
#
# New design: `_backup_journal_append` / `_backup_journal_record_created`
# write one NDJSON line to a scratch file per task. `_backup_journal_flush`
# is called once after each task completes (or at script exit) and
# merges the NDJSON buffer into the task's JSON file with a single
# Python invocation. O(N) Python calls, O(files) total work per task.
declare -gA BACKUP_JOURNAL_BUFFERS=()

_backup_journal_buffer_path() {
  local task=$1
  local dir="$MARKER_DIR/backups"
  # Only fork mkdir/chmod/chown once per run — $_PI_BACKUP_DIR_READY
  # is cleared on first successful setup and never reset.
  if [[ -z "${_PI_BACKUP_DIR_READY:-}" ]]; then
    mkdir -p "$dir"
    chmod 700 "$dir" 2>/dev/null || true
    chown root:root "$dir" 2>/dev/null || true
    _PI_BACKUP_DIR_READY=1
  fi
  printf '%s/.%s.ndjson' "$dir" "$task"
}

# Pure-bash NDJSON writer. Deliberately avoids Python — this runs in the
# hot path of backup_file, once per file. Emits a single JSON object per
# line with the fields --undo needs to restore. Encodes control bytes
# and backslashes/quotes minimally; paths containing those are rare in
# practice but we handle them rather than silently corrupt the journal.
_backup_journal_write_line() {
  local file=$1
  shift
  # Build a JSON object from key=value pairs. Values are treated as
  # strings unless the key starts with `_raw_` (then emitted verbatim
  # as a number/bool/null).
  local out="{"
  local first=1
  local pair key val
  for pair in "$@"; do
    key=${pair%%=*}
    val=${pair#*=}
    if (( first )); then first=0; else out+=", "; fi
    if [[ $key == _raw_* ]]; then
      key=${key#_raw_}
      out+="\"$key\": $val"
    else
      # Minimal JSON string escape: backslash, quote, control bytes.
      local esc=$val
      esc=${esc//\\/\\\\}
      esc=${esc//\"/\\\"}
      esc=${esc//$'\n'/\\n}
      esc=${esc//$'\r'/\\r}
      esc=${esc//$'\t'/\\t}
      out+="\"$key\": \"$esc\""
    fi
  done
  out+="}"
  printf '%s\n' "$out" >> "$file"
}

# Append an (original, backup) record to the current task's journal.
# Silent no-op when CURRENT_TASK is empty (startup, migrations).
_backup_journal_append() {
  local original=$1
  local backup=$2
  local task=${CURRENT_TASK:-}
  [[ -z "$task" ]] && return 0
  local buf
  buf=$(_backup_journal_buffer_path "$task")
  BACKUP_JOURNAL_BUFFERS["$task"]=$buf
  # Capture stat fields from the backup copy (cp -a preserves them, so
  # this matches the original). Silently fall back to null values on
  # stat failure — --undo tolerates missing perms in the journal.
  local mode_val="null" uid_val="null" gid_val="null" is_symlink_val="false"
  local link_target=""
  if [[ -L "$backup" || -e "$backup" ]]; then
    local stat_out
    # GNU: `stat -c "%a %u %g"`. BSD (macOS, dev hosts): `stat -f "%Lp %u %g"`.
    # Pi is always GNU, but supporting BSD keeps local testing viable.
    if stat_out=$(stat -c "%a %u %g" "$backup" 2>/dev/null) \
       || stat_out=$(stat -f "%Lp %u %g" "$backup" 2>/dev/null); then
      read -r mode_val uid_val gid_val <<<"$stat_out"
      # Mode is emitted as octal without the leading 0 — convert to int.
      if [[ $mode_val =~ ^[0-7]+$ ]]; then
        mode_val=$((8#$mode_val))
      else
        mode_val="null"
      fi
    fi
    if [[ -L "$backup" ]]; then
      is_symlink_val="true"
      link_target=$(readlink "$backup" 2>/dev/null || true)
    fi
  fi
  local -a pairs=(
    "kind=edit"
    "original=$original"
    "backup=$backup"
    "_raw_mode=$mode_val"
    "_raw_uid=$uid_val"
    "_raw_gid=$gid_val"
    "_raw_is_symlink=$is_symlink_val"
  )
  if [[ $is_symlink_val == "true" ]]; then
    pairs+=("link_target=$link_target")
  fi
  _backup_journal_write_line "$buf" "${pairs[@]}"
}

# Append a "created" record (no backup copy — the file didn't exist
# before this task ran). --undo removes the path instead of restoring
# from a backup. Silent no-op when CURRENT_TASK is empty.
_backup_journal_record_created() {
  local original=$1
  local task=${CURRENT_TASK:-}
  [[ -z "$task" ]] && return 0
  local buf
  buf=$(_backup_journal_buffer_path "$task")
  BACKUP_JOURNAL_BUFFERS["$task"]=$buf
  _backup_journal_write_line "$buf" \
    "kind=create" \
    "original=$original" \
    "_raw_created=true"
}

# Merge the NDJSON buffer for a task into its JSON journal. Called once
# per task (from the main task loop) and once more at script exit to
# catch any stragglers. Idempotent — once the buffer is consumed it's
# removed and the key is cleared.
_backup_journal_flush() {
  local task=${1:-}
  [[ -z "$task" ]] && return 0
  local buf=${BACKUP_JOURNAL_BUFFERS[$task]:-}
  [[ -z "$buf" || ! -s "$buf" ]] && { unset 'BACKUP_JOURNAL_BUFFERS[$task]'; rm -f "$buf" 2>/dev/null || true; return 0; }
  local dir="$MARKER_DIR/backups"
  local journal="$dir/${task}.json"
  BACKUP_JOURNAL_FILE="$journal" BACKUP_TASK="$task" \
  BACKUP_JOURNAL_BUFFER="$buf" \
  run_python <<'PY' || true
import json, os
from datetime import datetime, timezone
journal = os.environ["BACKUP_JOURNAL_FILE"]
task = os.environ["BACKUP_TASK"]
buf = os.environ["BACKUP_JOURNAL_BUFFER"]
try:
    with open(journal) as fh:
        data = json.load(fh)
except Exception:
    data = {}
runs = data.setdefault("runs", [])
stamp = os.environ.get("PI_RUN_STAMP") or datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
current = None
for r in runs:
    if r.get("run_id") == stamp:
        current = r
        break
if current is None:
    current = {"run_id": stamp, "task": task, "files": []}
    runs.append(current)
seen = {entry.get("original") for entry in current["files"]}
with open(buf) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        original = rec.get("original")
        if not original or original in seen:
            continue
        kind = rec.pop("kind", "edit")
        if kind == "create":
            current["files"].append({
                "original": original,
                "created": True,
            })
        else:
            entry = {
                "original": original,
                "backup": rec.get("backup"),
                "mode": rec.get("mode"),
                "uid": rec.get("uid"),
                "gid": rec.get("gid"),
                "is_symlink": rec.get("is_symlink", False),
            }
            if entry["is_symlink"] and rec.get("link_target"):
                entry["link_target"] = rec["link_target"]
            current["files"].append(entry)
        seen.add(original)
with open(journal, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.chmod(journal, 0o600)
PY
  rm -f "$buf" 2>/dev/null || true
  unset 'BACKUP_JOURNAL_BUFFERS[$task]'
}

# Flush every pending buffer. Called from EXIT trap so signals don't
# lose journal records.
_backup_journal_flush_all() {
  local task
  for task in "${!BACKUP_JOURNAL_BUFFERS[@]}"; do
    _backup_journal_flush "$task"
  done
}
