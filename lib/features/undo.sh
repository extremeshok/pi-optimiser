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
        original = entry.get("original")
        if entry.get("created"):
            print(f"  rm {original}")
        else:
            print(f"  {original} <- {entry.get('backup')}")
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

  # Capture the Python output so the shell can react to "REMOVED"
  # lines by disabling systemd units and reloading the daemon. Tee to
  # stdout so operators still see per-file results live.
  #
  # Defence-in-depth: the journal is root:root 0600, but we still
  # refuse to act on an `original` path that isn't absolute or that
  # contains a `..` component. A corrupted/malicious journal with
  # `original=/../etc/passwd` would otherwise have os.remove follow
  # the traversal. Same guard for `backup`.
  local _undo_out
  _undo_out=$(JOURNAL="$journal" run_python <<'PY'
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
removed = 0
missing = 0
rejected = 0
failed = 0

def _safe_path(p):
    """Reject traversal / relative paths in journal entries. Returns
    the path unchanged when safe, or None when unsafe.
    Defence-in-depth only; the journal is root:root 0600 in normal use."""
    if not isinstance(p, str) or not p:
        return None
    if not p.startswith("/"):
        return None
    # Any `..` segment is rejected outright — rules out /../etc/passwd,
    # /etc/foo/../../shadow, etc. os.path.normpath would resolve these
    # to the same file but accepting traversal forms lets a tampered
    # journal hide intent from audit logs.
    if ".." in p.split("/"):
        return None
    # Require canonical form — no doubled slashes, no trailing slash
    # (except on "/", which is never a valid target here). A benign
    # operator-typed path like /etc/foo will normalise to itself; a
    # crafted /etc/foo//../bar will differ and be rejected.
    if os.path.normpath(p) != p:
        return None
    return p

for entry in last.get("files", []):
    original = entry.get("original")
    if not original:
        continue
    safe_original = _safe_path(original)
    if safe_original is None:
        print(f"REJECT\t{original}\tunsafe path")
        rejected += 1
        continue
    # "created" record — task wrote a brand-new file, so --undo deletes
    # it. A file that was already removed by hand is not a failure; a
    # missing create record is logged to stderr but doesn't fail undo.
    if entry.get("created"):
        try:
            if os.path.lexists(safe_original):
                os.remove(safe_original)
                print(f"REMOVED\t{safe_original}")
                removed += 1
            else:
                print(f"GONE\t{safe_original}")
        except Exception as e:
            print(f"FAIL\t{safe_original}\t{e}")
            failed += 1
        continue
    backup = entry.get("backup")
    if not backup:
        continue
    safe_backup = _safe_path(backup)
    if safe_backup is None:
        print(f"REJECT\t{backup}\tunsafe backup path")
        rejected += 1
        continue
    # Use lexists so we detect a broken symlink backup too.
    if not os.path.lexists(safe_backup):
        print(f"MISSING\t{safe_backup}")
        missing += 1
        continue
    try:
        if entry.get("is_symlink"):
            # Re-create the symlink atomically. Older journals without
            # link_target fall back to reading the backup directly.
            target = entry.get("link_target") or os.readlink(safe_backup)
            if os.path.lexists(safe_original):
                os.remove(safe_original)
            os.symlink(target, safe_original)
        else:
            # copy2 preserves mtime but drops ownership — reapply mode,
            # uid, and gid from the journal afterwards so --undo fully
            # re-establishes the pristine state. Tolerate owner/mode
            # failures on exotic filesystems (e.g. FAT under /boot).
            shutil.copy2(safe_backup, safe_original)
            mode = entry.get("mode")
            uid = entry.get("uid")
            gid = entry.get("gid")
            if mode is not None:
                try:
                    os.chmod(safe_original, mode)
                except OSError:
                    pass
            if uid is not None and gid is not None:
                try:
                    os.chown(safe_original, uid, gid)
                except (OSError, PermissionError):
                    pass
        print(f"RESTORED\t{safe_original}\t<-\t{safe_backup}")
        restored += 1
    except Exception as e:
        print(f"FAIL\t{safe_original}\t{e}")
        failed += 1
print(f"SUMMARY\tlast_run={last.get('run_id')}\trestored={restored}\tremoved={removed}\tmissing={missing}\trejected={rejected}\tfailed={failed}")
PY
  ) || { log_error "undo: journal parse failed"; return 1; }
  printf '%s\n' "$_undo_out"

  # Systemd housekeeping: for every REMOVED line whose path is a unit
  # under /etc/systemd/ we stop + disable the unit before deletion
  # (the rm has already happened, but disable+daemon-reload is still
  # needed to drop the enable symlinks + tell systemd the unit is
  # gone). Drop-in directories get a plain daemon-reload.
  #
  # Also parse the SUMMARY line so missing/rejected/failed entries
  # surface as a non-zero exit. A silent "no backup, no restore" used
  # to sail through with exit 0 — operators would think the rollback
  # succeeded when nothing had actually been touched.
  local _reload_needed=0 _line _path _unit
  local _summary_line="" _rc=0
  while IFS= read -r _line; do
    [[ -z "$_line" ]] && continue
    case "$_line" in
      REMOVED$'\t'*)
        _path=${_line#REMOVED$'\t'}
        case "$_path" in
          /etc/systemd/system/*.service|/etc/systemd/system/*.timer|/etc/systemd/system/*.socket|/etc/systemd/system/*.path|/etc/systemd/system/*.mount)
            _unit=$(basename "$_path")
            systemctl disable --now "$_unit" >/dev/null 2>&1 || true
            _reload_needed=1
            ;;
          /etc/systemd/*)
            # Anything under /etc/systemd — unit file, drop-in dir,
            # journald.conf.d/, system.conf.d/, resolved.conf.d/, etc.
            # The *.service/*.timer branch above already handled enable
            # bookkeeping; here we just need a daemon-reload so the
            # dropped snippet stops taking effect immediately.
            _reload_needed=1
            ;;
        esac
        ;;
      SUMMARY$'\t'*)
        _summary_line=$_line
        ;;
    esac
  done <<< "$_undo_out"
  if (( _reload_needed == 1 )); then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  # Parse the SUMMARY line for missing/failed/rejected counts. These
  # are hard failures: a MISSING backup means the operator cleaned up
  # the restore target and there's nothing we can do; a REJECT means
  # the journal carried an unsafe path we refused to touch; a FAIL
  # means an exception was raised mid-restore. In all three cases the
  # state is not what the operator asked for, so we must exit non-zero.
  if [[ -n "$_summary_line" ]]; then
    local _kv _k _v _missing=0 _rejected=0 _failed=0
    for _kv in ${_summary_line#SUMMARY$'\t'}; do
      _k=${_kv%%=*}
      _v=${_kv#*=}
      case "$_k" in
        missing)  _missing=$_v ;;
        rejected) _rejected=$_v ;;
        failed)   _failed=$_v ;;
      esac
    done
    if (( _missing > 0 )); then
      log_error "undo: $_missing backup file(s) are gone — cannot restore; see MISSING lines above"
      _rc=1
    fi
    if (( _rejected > 0 )); then
      log_error "undo: $_rejected journal entry/entries refused as unsafe paths (see REJECT lines)"
      _rc=1
    fi
    if (( _failed > 0 )); then
      log_error "undo: $_failed file(s) failed to restore/remove; see FAIL lines above"
      _rc=1
    fi
  fi
  if (( _rc != 0 )); then
    # Don't clear the completion marker on partial failure — the
    # operator needs to investigate before the task re-runs.
    log_warn "Leaving completion marker for '$task' intact; resolve the errors above and retry"
    return "$_rc"
  fi

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
