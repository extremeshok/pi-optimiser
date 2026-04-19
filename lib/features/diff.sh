# ======================================================================
# lib/features/diff.sh — unified-diff preview for config.txt / cmdline
#
# Under `--diff`, ensure_config_* and cmdline_ensure_token call into
# pi_diff_propose instead of writing the real file. Proposals are kept
# per-target under $PI_CONFIG_PREVIEW_DIR and pi_diff_flush prints a
# `diff -u` of each target's current content against the would-be
# content at the end of the run.
#
# Functions: pi_diff_init, pi_diff_propose_full, pi_diff_flush
# Globals (read):  PI_CONFIG_PREVIEW, PI_CONFIG_PREVIEW_DIR
# Globals (write): PI_CONFIG_PREVIEW_DIR (on init)
# ======================================================================

# Helper used by pi_preview_<task> functions: replay a list of
# config.txt entries through ensure_config_key_value, which diverts
# writes to the preview buffer when PI_CONFIG_PREVIEW=1. Silently
# tolerates "unchanged" (rc=1) and parse failures (rc=2) so the preview
# doesn't bail early on one bad line.
pi_preview_apply_entries() {
  local target=${CONFIG_TXT_FILE:-/boot/firmware/config.txt}
  local entry
  for entry in "$@"; do
    ensure_config_key_value "$entry" "$target" >/dev/null 2>&1 || true
  done
}

pi_diff_init() {
  if [[ -z "${PI_CONFIG_PREVIEW_DIR:-}" ]]; then
    PI_CONFIG_PREVIEW_DIR=$(mktemp -d /tmp/pi-optimiser-diff.XXXXXX) || return 1
    export PI_CONFIG_PREVIEW_DIR
  fi
  if [[ ! -d "$PI_CONFIG_PREVIEW_DIR" ]]; then
    mkdir -p "$PI_CONFIG_PREVIEW_DIR" || return 1
  fi
  return 0
}

# Given a real target path and the full proposed content (as a single
# string), record the proposal. Subsequent calls for the same target
# accumulate — later proposals overwrite the buffer so the final buffer
# represents "what the file would look like after all edits".
pi_diff_propose_full() {
  local target=$1
  local content=$2
  pi_diff_init || return 1
  # Hash the target path so buffer names are filesystem-safe.
  local slug
  slug=$(printf '%s' "$target" | tr '/ .' '___')
  local buf="$PI_CONFIG_PREVIEW_DIR/$slug"
  printf '%s' "$content" > "$buf"
  # Also keep a pointer file mapping slug → real path so flush can show
  # the right --label value.
  printf '%s\n' "$target" > "$buf.path"
}

# Print a unified diff of every buffered proposal against its current
# content. Exits cleanly if nothing is buffered.
pi_diff_flush() {
  if [[ -z "${PI_CONFIG_PREVIEW_DIR:-}" || ! -d "$PI_CONFIG_PREVIEW_DIR" ]]; then
    log_info "--diff: no config changes were proposed"
    return 0
  fi
  shopt -s nullglob
  local any=0 buf target
  for buf in "$PI_CONFIG_PREVIEW_DIR"/*.path; do
    any=1
    target=$(<"$buf")
    local proposed="${buf%.path}"
    echo
    echo "=== would edit: $target ==="
    if [[ -f "$target" ]]; then
      if command -v diff >/dev/null 2>&1; then
        diff -u --label "$target (current)" --label "$target (proposed)" \
             "$target" "$proposed" || true
      else
        echo "--- proposed content ---"
        cat "$proposed"
      fi
    else
      echo "(target does not exist; full new contents below)"
      echo "--- proposed content ---"
      cat "$proposed"
    fi
  done
  shopt -u nullglob
  if [[ $any -eq 0 ]]; then
    log_info "--diff: no config.txt/cmdline.txt proposals captured"
  fi
  rm -rf "$PI_CONFIG_PREVIEW_DIR"
  return 0
}
