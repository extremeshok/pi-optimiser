# ======================================================================
# lib/util/python.sh — embedded Python helper
#
# Fixes the cross-cutting bug where Python heredocs in other helpers
# silently swallow exceptions. `run_python` runs a script on stdin,
# captures stdout, propagates non-zero exit, and logs stderr.
#
# Usage:
#   result=$(VAR1=x VAR2=y run_python <<'PY'
#   ...python source reading os.environ...
#   PY
#   )
#   # $? is 0 on success, non-zero on Python exception.
#
# Functions: run_python
# ======================================================================

# Run embedded Python from stdin. Propagates non-zero exit codes and
# forwards stderr to the log. Stdout is returned to the caller.
run_python() {
  local rc=0
  local stderr_file
  stderr_file=$(mktemp)
  python3 - 2>"$stderr_file" || rc=$?
  if [[ $rc -ne 0 && -s "$stderr_file" ]]; then
    while IFS= read -r line; do
      log_warn "python: $line"
    done <"$stderr_file"
  fi
  rm -f "$stderr_file"
  return $rc
}
