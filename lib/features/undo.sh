# ======================================================================
# lib/features/undo.sh — per-task undo using the backup journal
#
# Functions: pi_undo_task
#
# Reads $MARKER_DIR/backups/<task>.json (populated by backup_file) and
# restores each original file from its most recent .pi-optimiser.*
# backup. The task's completion marker is cleared so the task re-runs
# cleanly on the next invocation.
# ======================================================================

pi_undo_task() {
  local task=$1
  if [[ -z "$task" ]]; then
    log_error "--undo requires a task id"
    return 1
  fi
  # task flows into a filesystem path below; refuse anything that
  # could escape /etc/pi-optimiser/backups/.
  if ! validate_task_id "$task"; then
    log_error "--undo: invalid task id '$task' (expected snake_case)"
    return 1
  fi
  local journal="$MARKER_DIR/backups/${task}.json"
  if [[ ! -f "$journal" ]]; then
    # A task can complete without making file changes (the desired
    # state already matched, or it only wrote new files). In that case
    # there is nothing to restore — this is a clean no-op, not a
    # failure. We leave the completion marker intact so re-runs stay
    # idempotent.
    if is_task_done "$task"; then
      log_info "Task '$task' completed cleanly but made no file changes to undo"
      return 0
    fi
    log_warn "No backup journal for task '$task' at $journal"
    return 1
  fi

  if [[ ${DRY_RUN:-0} -eq 1 ]]; then
    log_info "[dry-run] would roll back backups recorded in $journal"
    JOURNAL="$journal" run_python <<'PY' 2>/dev/null || true
import json, os
with open(os.environ["JOURNAL"]) as fh:
    data = json.load(fh)
runs = data.get("runs", [])
if not runs:
    print("  (no runs recorded)")
else:
    last = runs[-1]
    for entry in last.get("files", []):
        print(f"  {entry.get('original')} <- {entry.get('backup')}")
PY
    return 0
  fi

  if [[ ${PI_NON_INTERACTIVE:-0} -ne 1 ]]; then
    echo "About to restore files from the most recent run of '$task'."
    echo "Journal: $journal"
    echo "Pass --yes to skip this prompt."
    read -r -p "Continue? [y/N] " answer </dev/tty
    case ${answer,,} in
      y|yes) ;;
      *) log_warn "Undo cancelled"; return 0 ;;
    esac
  fi

  JOURNAL="$journal" run_python <<'PY' || { log_error "undo: journal parse failed"; return 1; }
import json, os, shutil, sys
journal_path = os.environ["JOURNAL"]
with open(journal_path) as fh:
    data = json.load(fh)
runs = data.get("runs", [])
if not runs:
    print("NOJOURNAL")
    sys.exit(0)
last = runs[-1]  # most recent run is appended last
restored = 0
missing = 0
for entry in last.get("files", []):
    original = entry.get("original")
    backup = entry.get("backup")
    if not original or not backup:
        continue
    if not os.path.exists(backup):
        print(f"MISSING\t{backup}")
        missing += 1
        continue
    # Move original out of the way before copying the backup back so
    # the post-restore file has the backup's mtime/perms.
    try:
        shutil.copy2(backup, original)
        print(f"RESTORED\t{original}\t<-\t{backup}")
        restored += 1
    except Exception as e:
        print(f"FAIL\t{original}\t{e}")
print(f"SUMMARY\tlast_run={last.get('run_id')}\trestored={restored}\tmissing={missing}")
PY

  # Clear the completion marker so the task will be re-evaluated.
  clear_task_state "$task"
  log_info "Cleared state for task '$task'; next run will re-evaluate it"
}

# Roll back every task that has a journal in $MARKER_DIR/backups/,
# walking most-recent-run first. Useful after a problematic run when
# the operator wants to revert en masse.
pi_undo_all() {
  local dir="$MARKER_DIR/backups"
  if [[ ! -d "$dir" ]]; then
    log_info "No backup journals to undo at $dir"
    return 0
  fi
  if [[ ${DRY_RUN:-0} -eq 1 ]]; then
    log_info "[dry-run] would undo all journaled tasks"
    find "$dir" -maxdepth 1 -type f -name '*.json' \
      -printf '  %f\n' 2>/dev/null | sed 's/\.json$//'
    return 0
  fi
  if [[ ${PI_NON_INTERACTIVE:-0} -ne 1 ]]; then
    echo "About to --undo every task with a backup journal under $dir."
    echo "Pass --yes to skip this prompt."
    read -r -p "Continue? [y/N] " answer </dev/tty
    case ${answer,,} in
      y|yes) ;;
      *) log_warn "Undo-all cancelled"; return 0 ;;
    esac
  fi
  local rc=0 any_fail=0
  # Walk journals in reverse mtime order so the most recent run is
  # undone last (we prefer newest-first per-task, so older tasks
  # don't clobber newer ones when paths overlap).
  local journal tid
  while IFS= read -r journal; do
    tid=$(basename "$journal" .json)
    log_info "--undo --all: rolling back '$tid'"
    PI_NON_INTERACTIVE=1 pi_undo_task "$tid" || { any_fail=1; rc=$?; }
  done < <(find "$dir" -maxdepth 1 -type f -name '*.json' -printf '%T@ %p\n' \
           2>/dev/null | sort -rn | awk '{print $2}')
  if (( any_fail == 0 )); then
    log_info "All journaled tasks rolled back"
    # Everything is rolled back; the reboot-required flag is no
    # longer meaningful. Clear it so the next --report doesn't
    # scream REBOOT REQUIRED.
    write_json_field "$CONFIG_OPTIMISER_STATE" "reboot.required" "false"
    write_json_field "$CONFIG_OPTIMISER_STATE" "reboot.cleared_at" \
      "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
  else
    log_warn "Some tasks failed to roll back (last rc=$rc)"
  fi
  return $rc
}
