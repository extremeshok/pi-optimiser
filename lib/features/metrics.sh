# ======================================================================
# lib/features/metrics.sh — Prometheus textfile-collector emitter
#
# Writes a .prom file summarising the most recent run so node-exporter's
# textfile collector can surface pi-optimiser state in Prometheus.
#
# Output path is picked in order:
#   1. $PI_METRICS_PATH (explicit override; config.yaml or env)
#   2. /var/lib/node_exporter/textfile_collector/pi-optimiser.prom
#      (prometheus-node-exporter's default; directory must exist)
#   3. /etc/pi-optimiser/metrics/pi-optimiser.prom (fallback)
#
# Disabled entirely when PI_METRICS_ENABLED=0 or under --dry-run. The
# emitter is a no-op if no task results are present (e.g. pure info-only
# invocations).
#
# Functions: pi_metrics_write
# Globals (read): SUMMARY_COMPLETED, SUMMARY_SKIPPED, SUMMARY_FAILED,
#                 PI_TASK_VERSION, PI_METRICS_ENABLED, PI_METRICS_PATH,
#                 DRY_RUN, STATE_JSON_FILE, CONFIG_OPTIMISER_STATE
# ======================================================================

PI_METRICS_DEFAULT_PATH="/var/lib/node_exporter/textfile_collector/pi-optimiser.prom"
PI_METRICS_FALLBACK_PATH="/etc/pi-optimiser/metrics/pi-optimiser.prom"

_pi_metrics_target() {
  if [[ -n "${PI_METRICS_PATH:-}" ]]; then
    printf '%s\n' "$PI_METRICS_PATH"
    return 0
  fi
  if [[ -d "$(dirname "$PI_METRICS_DEFAULT_PATH")" ]]; then
    printf '%s\n' "$PI_METRICS_DEFAULT_PATH"
    return 0
  fi
  printf '%s\n' "$PI_METRICS_FALLBACK_PATH"
}

pi_metrics_write() {
  if [[ "${PI_METRICS_ENABLED:-1}" != "1" ]]; then
    return 0
  fi
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    return 0
  fi
  local target tmp
  target=$(_pi_metrics_target)
  local dir
  dir=$(dirname "$target")
  if ! mkdir -p "$dir" 2>/dev/null; then
    log_warn "metrics: cannot create $dir; skipping .prom emit"
    return 0
  fi
  tmp="${target}.$$.tmp"
  # Emit atomically via tmp + rename so readers never see a half-written
  # file. Text-format spec is stable; see
  # https://prometheus.io/docs/instrumenting/exposition_formats/
  {
    printf '# HELP pi_optimiser_task_status Per-task status from the most recent run.\n'
    printf '# TYPE pi_optimiser_task_status gauge\n'
    local entry task
    for entry in "${SUMMARY_COMPLETED[@]}"; do
      task=${entry%% *}
      printf 'pi_optimiser_task_status{task="%s",status="completed"} 1\n' "$task"
    done
    for entry in "${SUMMARY_FAILED[@]}"; do
      task=${entry%% *}
      printf 'pi_optimiser_task_status{task="%s",status="failed"} 1\n' "$task"
    done
    for entry in "${SUMMARY_SKIPPED[@]}"; do
      task=${entry%% *}
      printf 'pi_optimiser_task_status{task="%s",status="skipped"} 1\n' "$task"
    done
    printf '# HELP pi_optimiser_tasks_completed_total Tasks completed in the most recent run.\n'
    printf '# TYPE pi_optimiser_tasks_completed_total gauge\n'
    printf 'pi_optimiser_tasks_completed_total %d\n' "${#SUMMARY_COMPLETED[@]}"
    printf '# HELP pi_optimiser_tasks_failed_total Tasks failed in the most recent run.\n'
    printf '# TYPE pi_optimiser_tasks_failed_total gauge\n'
    printf 'pi_optimiser_tasks_failed_total %d\n' "${#SUMMARY_FAILED[@]}"
    printf '# HELP pi_optimiser_tasks_skipped_total Tasks skipped in the most recent run.\n'
    printf '# TYPE pi_optimiser_tasks_skipped_total gauge\n'
    printf 'pi_optimiser_tasks_skipped_total %d\n' "${#SUMMARY_SKIPPED[@]}"
    printf '# HELP pi_optimiser_last_run_timestamp_seconds Unix time of the most recent run.\n'
    printf '# TYPE pi_optimiser_last_run_timestamp_seconds gauge\n'
    printf 'pi_optimiser_last_run_timestamp_seconds %d\n' "$(date +%s)"
    printf '# HELP pi_optimiser_reboot_required 1 if the most recent run flagged a reboot.\n'
    printf '# TYPE pi_optimiser_reboot_required gauge\n'
    if declare -F pi_reboot_required >/dev/null 2>&1 && pi_reboot_required; then
      printf 'pi_optimiser_reboot_required 1\n'
    else
      printf 'pi_optimiser_reboot_required 0\n'
    fi
    printf '# HELP pi_optimiser_version_info Installed pi-optimiser version.\n'
    printf '# TYPE pi_optimiser_version_info gauge\n'
    printf 'pi_optimiser_version_info{version="%s"} 1\n' "${SCRIPT_VERSION:-unknown}"
  } >"$tmp" 2>/dev/null || {
    log_warn "metrics: failed writing $tmp"
    rm -f "$tmp"
    return 0
  }
  if ! mv -f "$tmp" "$target"; then
    log_warn "metrics: failed renaming $tmp to $target"
    rm -f "$tmp"
    return 0
  fi
  chmod 644 "$target" 2>/dev/null || true
  log_info "Wrote Prometheus metrics to $target"
}
