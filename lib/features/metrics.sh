# ======================================================================
# lib/features/metrics.sh — Prometheus textfile-collector emitter
#
# Writes a .prom file summarising the most recent run so node-exporter's
# textfile collector can surface pi-optimiser state in Prometheus.
#
# Output path is picked in order:
#   1. $PI_METRICS_PATH (explicit override; config.yaml or env)
#   2. /var/lib/node_exporter/textfile_collector/pi-optimiser.prom
#      (node-exporter's default; directory must exist)
#   3. /etc/pi-optimiser/metrics/pi-optimiser.prom (fallback)
#
# Disabled when PI_METRICS_ENABLED=0 or under --dry-run.
#
# Functions: pi_metrics_write
# Globals (read): SUMMARY_COMPLETED, SUMMARY_FAILED, SUMMARY_SKIPPED,
#                 PI_METRICS_ENABLED, PI_METRICS_PATH, DRY_RUN,
#                 SCRIPT_VERSION
# ======================================================================

PI_METRICS_DEFAULT_PATH="/var/lib/node_exporter/textfile_collector/pi-optimiser.prom"
PI_METRICS_FALLBACK_PATH="/etc/pi-optimiser/metrics/pi-optimiser.prom"

# Emit one `pi_optimiser_task_status{task=...,status=...} 1` line per
# entry. SUMMARY_* entries are either bare task ids ("fstab") or
# "task (annotation)" strings (e.g. "fstab (frozen)"); stripping at the
# first space recovers the id in both cases.
_pi_metrics_emit_status() {
  local status=$1 entry task
  shift
  for entry in "$@"; do
    task=${entry%% *}
    printf 'pi_optimiser_task_status{task="%s",status="%s"} 1\n' "$task" "$status"
  done
}

pi_metrics_write() {
  [[ "${PI_METRICS_ENABLED:-1}" == "1" ]] || return 0
  [[ "${DRY_RUN:-0}" == "0" ]] || return 0

  local target
  if [[ -n "${PI_METRICS_PATH:-}" ]]; then
    if declare -F validate_metrics_path >/dev/null 2>&1 \
        && ! validate_metrics_path "$PI_METRICS_PATH"; then
      log_warn "metrics: invalid metrics path '$PI_METRICS_PATH'; skipping .prom emit"
      return 0
    fi
    target=$PI_METRICS_PATH
  elif [[ -d "$(dirname "$PI_METRICS_DEFAULT_PATH")" ]]; then
    target=$PI_METRICS_DEFAULT_PATH
  else
    target=$PI_METRICS_FALLBACK_PATH
  fi
  local dir=${target%/*}
  if ! mkdir -p "$dir" 2>/dev/null; then
    log_warn "metrics: cannot create $dir; skipping .prom emit"
    return 0
  fi

  # Reboot-required is an integer for Prometheus clarity.
  local reboot_flag=0
  if declare -F pi_reboot_required >/dev/null 2>&1 && pi_reboot_required; then
    reboot_flag=1
  fi

  # Write atomically via tmp + rename so readers never see a half-file.
  # Use mktemp with a randomized suffix in the same dir as $target so
  # the rename is atomic on the same filesystem. The previous
  # "${target}.$$.tmp" form was predictable — if $dir is writable by
  # an unprivileged user (node_exporter's textfile_collector dir often
  # is owned by node_exporter:node_exporter, mode 0755 or 0775), that
  # user could pre-create a symlink at the predictable path and the
  # root-run shell would write through it.
  local tmp
  tmp=$(mktemp "${dir}/pi-optimiser.prom.XXXXXX") || {
    log_warn "metrics: cannot create tmp in $dir; skipping .prom emit"
    return 0
  }
  # mktemp creates with 0600; chmod now so after rename readers can
  # pick it up. Don't defer to after rename (brief 0600 window is fine
  # on textfile_collector since node-exporter polls every 15s, but
  # pre-rename set is cleaner).
  chmod 0644 "$tmp" 2>/dev/null || true
  local _metrics_cleanup
  # shellcheck disable=SC2064
  trap "rm -f '$tmp'" RETURN
  {
    cat <<PROM
# HELP pi_optimiser_task_status Per-task status from the most recent run.
# TYPE pi_optimiser_task_status gauge
PROM
    _pi_metrics_emit_status completed "${SUMMARY_COMPLETED[@]}"
    _pi_metrics_emit_status failed    "${SUMMARY_FAILED[@]}"
    _pi_metrics_emit_status skipped   "${SUMMARY_SKIPPED[@]}"
    cat <<PROM
# HELP pi_optimiser_tasks_completed_total Tasks completed in the most recent run.
# TYPE pi_optimiser_tasks_completed_total gauge
pi_optimiser_tasks_completed_total ${#SUMMARY_COMPLETED[@]}
# HELP pi_optimiser_tasks_failed_total Tasks failed in the most recent run.
# TYPE pi_optimiser_tasks_failed_total gauge
pi_optimiser_tasks_failed_total ${#SUMMARY_FAILED[@]}
# HELP pi_optimiser_tasks_skipped_total Tasks skipped in the most recent run.
# TYPE pi_optimiser_tasks_skipped_total gauge
pi_optimiser_tasks_skipped_total ${#SUMMARY_SKIPPED[@]}
# HELP pi_optimiser_last_run_timestamp_seconds Unix time of the most recent run.
# TYPE pi_optimiser_last_run_timestamp_seconds gauge
pi_optimiser_last_run_timestamp_seconds $(date +%s)
# HELP pi_optimiser_reboot_required 1 if the most recent run flagged a reboot.
# TYPE pi_optimiser_reboot_required gauge
pi_optimiser_reboot_required $reboot_flag
# HELP pi_optimiser_version_info Installed pi-optimiser version.
# TYPE pi_optimiser_version_info gauge
pi_optimiser_version_info{version="${SCRIPT_VERSION:-unknown}"} 1
PROM
  } >"$tmp" 2>/dev/null || {
    log_warn "metrics: failed writing $tmp"
    return 0
  }
  if ! mv -f -- "$tmp" "$target"; then
    log_warn "metrics: failed renaming $tmp to $target"
    return 0
  fi
  chmod 644 -- "$target" 2>/dev/null || true
  log_info "Wrote Prometheus metrics to $target"
}
