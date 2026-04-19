# shellcheck disable=SC2034
# ======================================================================
# lib/util/state.sh — persistent state tracking (schema v2, JSON)
#
# Layout on disk (introduced in 8.0.0):
#   /etc/pi-optimiser/state.json      # task completion records
#   /etc/pi-optimiser/state.schema    # integer; currently "2"
#   /etc/pi-optimiser/state.pi-optimiser.v1.bak
#                                     # one-shot copy of the legacy CSV
#
# Legacy v1 (pre-8.0.0) was a pipe-CSV at /etc/pi-optimiser/state.
# pi_state_migrate() converts v1→v2 on first startup under 8.x.
#
# Functions: ensure_marker_store, pi_state_schema_version,
#            pi_state_migrate, set_task_state, clear_task_state,
#            get_task_state, is_task_done,
#            read_json_field, write_json_field
# Globals (read):  MARKER_DIR, STATE_FILE (legacy path, still referenced
#                  by ensure_marker_store/migration), STATE_JSON_FILE,
#                  STATE_SCHEMA_FILE, CONFIG_OPTIMISER_STATE,
#                  PI_TASK_VERSION (task registry)
# Globals (write): TASK_STATE_STATUS, TASK_STATE_TIMESTAMP,
#                  TASK_STATE_DESC, TASK_STATE_VERSION
# ======================================================================

# Schema version this codebase targets.
PI_STATE_SCHEMA_TARGET=2

# JSON state files live next to the (now legacy) CSV file for discoverability.
STATE_JSON_FILE="$MARKER_DIR/state.json"
STATE_SCHEMA_FILE="$MARKER_DIR/state.schema"

# Create optimiser state directory and baseline files if missing.
ensure_marker_store() {
  if [[ ! -d "$MARKER_DIR" ]]; then
    mkdir -p "$MARKER_DIR"
    chmod 755 "$MARKER_DIR"
  fi
  # Touch the legacy file for backward compat with old tooling that
  # grepped for it; pi_state_migrate() will migrate + rename it.
  if [[ ! -f "$STATE_FILE" && ! -f "$STATE_JSON_FILE" ]]; then
    touch "$STATE_FILE"
    chmod 644 "$STATE_FILE"
  fi
  pi_state_migrate
}

# Return the installed schema version, defaulting to 1 if absent.
pi_state_schema_version() {
  if [[ -f "$STATE_SCHEMA_FILE" ]]; then
    cat "$STATE_SCHEMA_FILE"
  else
    echo 1
  fi
}

# Bring the state files forward to PI_STATE_SCHEMA_TARGET.
pi_state_migrate() {
  local current
  current=$(pi_state_schema_version)
  # Downgrade guard: if a future version wrote state.schema > target,
  # stop rather than quietly mis-parse newer fields as older.
  if (( current > PI_STATE_SCHEMA_TARGET )); then
    log_error "state.schema=v$current is newer than this build's target (v$PI_STATE_SCHEMA_TARGET)."
    log_error "Refusing to read forward-incompatible state. Either upgrade pi-optimiser"
    log_error "or move $STATE_JSON_FILE + $STATE_SCHEMA_FILE aside."
    exit 1
  fi
  if (( current >= PI_STATE_SCHEMA_TARGET )); then
    # Defensive: validate state.json is still parseable. A hand-edit
    # with a trailing comma silently resets everywhere else; we want
    # a loud warning with the original file preserved.
    if [[ -f "$STATE_JSON_FILE" ]]; then
      if ! STATE_JSON_PATH="$STATE_JSON_FILE" run_python <<'PY' >/dev/null 2>&1
import json, os, sys
with open(os.environ["STATE_JSON_PATH"]) as fh:
    json.load(fh)
PY
      then
        local _corrupt
        _corrupt="${STATE_JSON_FILE}.corrupt-$(date +%Y%m%d%H%M%S)"
        log_warn "state.json is malformed; moving aside to $_corrupt"
        mv -f "$STATE_JSON_FILE" "$_corrupt" 2>/dev/null || true
        echo '{"schema_version": 2, "tasks": {}}' > "$STATE_JSON_FILE"
        chmod 644 "$STATE_JSON_FILE"
      fi
    fi
    return 0
  fi
  log_info "Migrating state schema v$current -> v$PI_STATE_SCHEMA_TARGET"
  if (( current == 1 )); then
    _pi_state_migrate_v1_v2
    current=2
  fi
  echo "$current" > "$STATE_SCHEMA_FILE"
  chmod 644 "$STATE_SCHEMA_FILE"
}

# Convert legacy pipe-CSV state to JSON. Keeps a .v1.bak copy.
_pi_state_migrate_v1_v2() {
  local legacy=$STATE_FILE
  local target=$STATE_JSON_FILE
  if [[ -f "$target" ]]; then
    return 0  # target already exists; nothing to migrate
  fi
  LEGACY="$legacy" TARGET="$target" run_python <<'PY' || return 1
import json, os
data = {"schema_version": 2, "tasks": {}}
legacy = os.environ["LEGACY"]
target = os.environ["TARGET"]
if os.path.exists(legacy):
    with open(legacy) as fh:
        for line in fh:
            parts = line.rstrip("\n").split("|", 3)
            if len(parts) != 4:
                continue
            task, status, ts, desc = parts
            if not task:
                continue
            data["tasks"][task] = {
                "status": status,
                "timestamp": ts,
                "description": desc,
                "task_version": "0.0.0",  # unknown; pre-migration
            }
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  chmod 644 "$target"
  if [[ -f "$legacy" ]]; then
    local bak="${legacy}.pi-optimiser.v1.bak"
    mv "$legacy" "$bak" 2>/dev/null && log_info "Archived legacy v1 state at $bak"
  fi
}

# Fetch dot-delimited key from JSON file using run_python helper.
read_json_field() {
  local file=$1
  local key=$2
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  STATE_JSON_PATH="$file" STATE_JSON_KEY="$key" run_python <<'PY' || return 1
import json, os, sys
path = os.environ['STATE_JSON_PATH']
key = os.environ['STATE_JSON_KEY']
try:
    with open(path) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(1)
value = data
for part in key.split('.'):
    if isinstance(value, dict) and part in value:
        value = value[part]
    else:
        sys.exit(1)
if value is None:
    sys.exit(1)
print(value)
PY
}

# Persist dot-delimited key/value pair to JSON, creating parents as needed.
write_json_field() {
  local file=$1
  local key=$2
  local value=$3
  STATE_JSON_PATH="$file" STATE_JSON_KEY="$key" STATE_JSON_VALUE="$value" run_python <<'PY'
import json, os
path = os.environ['STATE_JSON_PATH']
key = os.environ['STATE_JSON_KEY']
value = os.environ['STATE_JSON_VALUE']
os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
try:
    with open(path) as fh:
        data = json.load(fh)
except Exception:
    data = {}
ref = data
parts = key.split('.')
for part in parts[:-1]:
    ref = ref.setdefault(part, {})
ref[parts[-1]] = value
with open(path, 'w') as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write('\n')
PY
}

# Record task completion metadata to the JSON state file.
set_task_state() {
  local task=$1
  local status=$2
  local desc=$3
  local task_version=${PI_TASK_VERSION[$task]:-1.0.0}
  ensure_marker_store
  STATE_JSON_PATH="$STATE_JSON_FILE" \
  PI_TASK="$task" PI_STATUS="$status" PI_DESC="$desc" \
  PI_TSV="$task_version" run_python <<'PY'
import json, os
from datetime import datetime, timezone
path = os.environ["STATE_JSON_PATH"]
os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
try:
    with open(path) as fh:
        data = json.load(fh)
except Exception:
    data = {}
data.setdefault("schema_version", 2)
tasks = data.setdefault("tasks", {})
tasks[os.environ["PI_TASK"]] = {
    "status": os.environ["PI_STATUS"],
    "timestamp": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
    "description": os.environ["PI_DESC"],
    "task_version": os.environ["PI_TSV"],
}
with open(path, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  chmod 644 "$STATE_JSON_FILE"
}

# Remove an entry from the JSON state file.
clear_task_state() {
  local task=$1
  if [[ ! -f "$STATE_JSON_FILE" ]]; then
    return
  fi
  STATE_JSON_PATH="$STATE_JSON_FILE" PI_TASK="$task" run_python <<'PY' || return 1
import json, os
path = os.environ["STATE_JSON_PATH"]
try:
    with open(path) as fh:
        data = json.load(fh)
except Exception:
    data = {}
tasks = data.get("tasks", {})
tasks.pop(os.environ["PI_TASK"], None)
data["tasks"] = tasks
with open(path, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

# Populate TASK_STATE_* globals from the JSON state file. Returns 0 on
# hit, 1 on miss.
get_task_state() {
  local task=$1
  TASK_STATE_STATUS=""
  TASK_STATE_TIMESTAMP=""
  TASK_STATE_DESC=""
  TASK_STATE_VERSION=""
  if [[ ! -f "$STATE_JSON_FILE" ]]; then
    return 1
  fi
  local line
  line=$(STATE_JSON_PATH="$STATE_JSON_FILE" PI_TASK="$task" run_python <<'PY'
import json, os, sys
path = os.environ["STATE_JSON_PATH"]
task = os.environ["PI_TASK"]
try:
    with open(path) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(1)
rec = (data.get("tasks") or {}).get(task)
if rec is None:
    sys.exit(1)
print("%s\t%s\t%s\t%s" % (
    rec.get("status", ""),
    rec.get("timestamp", ""),
    rec.get("description", ""),
    rec.get("task_version", ""),
))
PY
) || return 1
  IFS=$'\t' read -r TASK_STATE_STATUS TASK_STATE_TIMESTAMP TASK_STATE_DESC TASK_STATE_VERSION <<< "$line"
  return 0
}

# Return success when a task previously completed successfully.
is_task_done() {
  if get_task_state "$1"; then
    [[ "$TASK_STATE_STATUS" == "completed" ]]
  else
    return 1
  fi
}
