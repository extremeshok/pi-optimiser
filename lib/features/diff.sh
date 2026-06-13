# ======================================================================
# lib/features/diff.sh — unified-diff preview for config.txt / cmdline
#
# Under `--diff`, ensure_config_key_value / ensure_config_line /
# cmdline_ensure_token call `_pi_config_preview_target` (in
# lib/util/config_txt.sh) to divert writes to a scratch buffer under
# $PI_CONFIG_PREVIEW_DIR. pi_diff_flush prints a `diff -u` of each
# buffered target against the real file at end-of-run.
#
# Functions: pi_preview_apply_entries, pi_diff_flush
# Globals (read):  PI_CONFIG_PREVIEW_DIR, CONFIG_TXT_FILE
# ======================================================================

# Replay a list of config.txt entries through the SAME dispatch +
# section as run_<task> (_pi_config_apply_one), which buffers under
# PI_CONFIG_PREVIEW=1. "Unchanged" (rc=1) and parse failures (rc=2) are
# swallowed so a preview doesn't bail on one bad line.
#
# Usage:
#   pi_preview_apply_entries <entry>...               # section 'all'
#   pi_preview_apply_entries --section pi5 <entry>...  # explicit section
#
# The --section form lets previews of [pi5]-scoped tasks (pi5_fan,
# pcie_gen3, ...) match where run_<task> actually writes.
pi_preview_apply_entries() {
  local target=${CONFIG_TXT_FILE:-/boot/firmware/config.txt}
  local section=all
  if [[ ${1:-} == --section ]]; then
    section=${2:-all}
    shift 2
  fi
  local entry
  for entry in "$@"; do
    _pi_config_apply_one "$entry" "$target" "$section" >/dev/null 2>&1 || true
  done
}

# Print a unified diff of every buffered proposal against its current
# content. Exits cleanly if nothing is buffered.
pi_diff_flush() {
  if [[ -z "${PI_CONFIG_PREVIEW_DIR:-}" || ! -d "$PI_CONFIG_PREVIEW_DIR" ]]; then
    log_info "--diff: no config changes were proposed"
    return 0
  fi
  local -a paths=("$PI_CONFIG_PREVIEW_DIR"/*.path)
  # Glob that matches nothing leaves the literal pattern in paths[0].
  if [[ ! -f "${paths[0]:-}" ]]; then
    log_info "--diff: no config.txt/cmdline.txt proposals captured"
    rm -rf "$PI_CONFIG_PREVIEW_DIR"
    return 0
  fi
  local buf target proposed
  for buf in "${paths[@]}"; do
    target=$(<"$buf")
    proposed="${buf%.path}"
    echo
    echo "=== would edit: $target ==="
    if [[ -f "$target" ]]; then
      diff -u --label "$target (current)" --label "$target (proposed)" \
        "$target" "$proposed" || true
    else
      echo "(target does not exist; full new contents below)"
      cat "$proposed"
    fi
  done
  rm -rf "$PI_CONFIG_PREVIEW_DIR"
}
