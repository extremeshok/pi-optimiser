# ======================================================================
# lib/util/backup.sh — timestamped file backups with rotation + journal
#
# Functions: backup_file, prune_backups
# Globals (read):  BACKED_UP, BACKUP_KEEP_COUNT, CURRENT_TASK,
#                  MARKER_DIR
#
# For every `.pi-optimiser.<ts>` backup produced, we append a JSON
# record to $MARKER_DIR/backups/<task>.json so `--undo <task>` can
# locate what to restore. The journal is append-only within a run —
# the first backup for a (task,original_path) pair wins, further
# edits of the same file are *not* re-logged (matches BACKED_UP).
# ======================================================================

# Keep the N most recent .pi-optimiser.* backups for each backed-up path.
# Defaults to 5 if BACKUP_KEEP_COUNT is unset.
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
  while IFS= read -r entry; do
    [[ -n "$entry" ]] && backups+=("$entry")
  done < <(find "$parent" -maxdepth 1 -type f -name "${base}.pi-optimiser.*" 2>/dev/null | sort)
  local total=${#backups[@]}
  if (( total <= keep )); then
    return 0
  fi
  local drop=$(( total - keep ))
  local i
  for (( i=0; i<drop; i++ )); do
    rm -f "${backups[i]}" 2>/dev/null || true
  done
}

# Copy original file to timestamped backup once per run, log the pairing
# into the current task's journal, and prune old backups.
backup_file() {
  local path=$1
  if [[ ! -f "$path" ]]; then
    return
  fi
  if [[ -n ${BACKED_UP[$path]:-} ]]; then
    return
  fi
  local backup
  backup="${path}.pi-optimiser.$(date +%Y%m%d%H%M%S)"
  cp "$path" "$backup"
  BACKED_UP[$path]="$backup"
  log_info "Created backup $backup"
  prune_backups "$path"
  _backup_journal_append "$path" "$backup"
}

# Append an (original, backup) record to the current task's journal.
# Silent no-op when CURRENT_TASK is empty (startup, migrations).
_backup_journal_append() {
  local original=$1
  local backup=$2
  local task=${CURRENT_TASK:-}
  [[ -z "$task" ]] && return 0
  local dir="$MARKER_DIR/backups"
  local file="$dir/${task}.json"
  mkdir -p "$dir"
  chmod 755 "$dir" 2>/dev/null || true
  BACKUP_JOURNAL_FILE="$file" BACKUP_TASK="$task" \
  BACKUP_ORIGINAL="$original" BACKUP_COPY="$backup" \
  run_python <<'PY' || true
import json, os
from datetime import datetime, timezone
file = os.environ["BACKUP_JOURNAL_FILE"]
task = os.environ["BACKUP_TASK"]
original = os.environ["BACKUP_ORIGINAL"]
copy = os.environ["BACKUP_COPY"]
try:
    with open(file) as fh:
        data = json.load(fh)
except Exception:
    data = {}
runs = data.setdefault("runs", [])
# Group by the per-run timestamp the script writes once per run.
stamp = os.environ.get("PI_RUN_STAMP") or datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
current = None
for r in runs:
    if r.get("run_id") == stamp:
        current = r
        break
if current is None:
    current = {"run_id": stamp, "task": task, "files": []}
    runs.append(current)
for entry in current["files"]:
    if entry.get("original") == original:
        break
else:
    current["files"].append({"original": original, "backup": copy})
with open(file, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}
