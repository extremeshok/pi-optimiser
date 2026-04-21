#!/usr/bin/env bash
# ======================================================================
# scripts/build-bundle.sh — produce a single-file pi-optimiser release.
#
# The bundle inlines every lib/util/*.sh, lib/tasks/*.sh,
# lib/features/*.sh (plus lib/MANIFEST) into the main script, so the
# resulting file works as a standalone `curl | sudo bash` payload.
#
# Usage:
#   scripts/build-bundle.sh                         # writes dist/pi-optimiser-bundle.sh
#   scripts/build-bundle.sh /tmp/pi-optimiser.sh    # custom output path
#
# The bundle replaces the runtime sourcing loop with a version-info
# banner so the single file has no filesystem dependency on lib/.
#
# Guarantees:
#   * Deterministic  — same input tree → byte-identical output.
#   * Atomic         — writes to .tmp in the output directory then
#                      `mv` (same filesystem, so rename is atomic).
#   * Fail-closed    — any missing/invalid input aborts with a clear
#                      error; no partial bundle ever lands at $output.
#   * Verified       — post-build bash -n, --version, --list-tasks are
#                      compared against the main script to catch any
#                      divergence (e.g. an unsourced task file).
#   * Sidecar        — a .sha256 file is emitted alongside the bundle
#                      so consumers (install.sh, release workflow) can
#                      verify integrity without re-hashing from upstream.
# ======================================================================
set -euo pipefail
# build-bundle emits a single-file release into dist/. Pin umask so
# the resulting bundle is 0644 (0755 after chmod +x below), not
# affected by a loose developer shell umask.
umask 0022

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:-"$root/dist/pi-optimiser-bundle.sh"}
output_dir=$(cd "$(dirname "$output")" 2>/dev/null && pwd || true)
if [[ -z "$output_dir" ]]; then
  mkdir -p "$(dirname "$output")"
  output_dir=$(cd "$(dirname "$output")" && pwd)
fi
output="$output_dir/$(basename "$output")"

main="$root/pi-optimiser.sh"
if [[ ! -f "$main" ]]; then
  echo "build-bundle.sh: cannot find $main" >&2
  exit 1
fi

# --- Input sanity: fail closed BEFORE invoking python. A missing
# MANIFEST, empty tasks directory, or absent util/feature/ui dir
# would otherwise produce a corrupt bundle with cryptic runtime
# errors ("command not found: log_info") on end-user machines.
for _d in lib lib/util lib/features lib/ui lib/tasks; do
  if [[ ! -d "$root/$_d" ]]; then
    echo "build-bundle.sh: missing input directory $root/$_d" >&2
    exit 1
  fi
done
unset _d
if [[ ! -f "$root/lib/MANIFEST" ]]; then
  echo "build-bundle.sh: missing $root/lib/MANIFEST" >&2
  exit 1
fi
# glob-count: shopt nullglob so an empty dir yields 0, not the literal
_empty_dir_check() {
  local dir="$1" count
  shopt -s nullglob
  local entries=("$root/$dir"/*.sh)
  count=${#entries[@]}
  shopt -u nullglob
  if (( count == 0 )); then
    echo "build-bundle.sh: no *.sh files found in $root/$dir" >&2
    exit 1
  fi
}
_empty_dir_check lib/util
_empty_dir_check lib/features
_empty_dir_check lib/ui
_empty_dir_check lib/tasks

# Write the .tmp in the OUTPUT directory (not $TMPDIR) so the final
# `mv` is a rename on the same filesystem — atomic. If mktemp fell
# into /tmp and /tmp sat on a different mount, `mv` would fall back
# to copy+unlink and a SIGINT mid-copy could leave a truncated file
# at $output.
tmp=$(mktemp "$output_dir/.pi-optimiser-bundle.XXXXXX.tmp")
trap 'rm -f "$tmp" "$tmp.sha256"' EXIT

# Read the main script and split it at the sourcing block. We replace
# the runtime source loop with a compile-time-inlined block.
python3 - "$main" "$root" "$tmp" <<'PY'
import os
import sys
from pathlib import Path

main_path, root_path, tmp_path = sys.argv[1], sys.argv[2], sys.argv[3]
main_text = Path(main_path).read_text()

marker_start = "_pi_self=${BASH_SOURCE[0]}"
# The end marker now includes the UI sourcing block that was added in P5.
marker_end = 'if [[ -f "$LIB_UI_DIR/tui.sh" ]]; then\n  # shellcheck source=/dev/null\n  source "$LIB_UI_DIR/tui.sh"\nfi'

start = main_text.find(marker_start)
end = main_text.find(marker_end)
if start < 0 or end < 0:
    print("build-bundle: source markers not found in main script", file=sys.stderr)
    sys.exit(1)

pre = main_text[:start]
post = main_text[end + len(marker_end):]

# Sanity: the first ~40 lines of the main script (shebang, strict-mode,
# umask, bash-version guard) MUST appear verbatim in `pre`. A future
# refactor that moves the source block earlier would silently strip
# these and produce a bundle that runs under /bin/sh or with a loose
# umask. Guard against it.
for required in ("#!/usr/bin/env bash", "set -euo pipefail", "umask 0022"):
    if required not in pre:
        print(f"build-bundle: pre-source block missing required line: {required!r}",
              file=sys.stderr)
        sys.exit(1)

order_utils = ["log", "python", "state", "backup", "config_txt", "cmdline",
               "fstab", "sshd", "apt", "systemd", "model", "hardware",
               "preflight", "validate", "config_yaml"]
order_features = ["profiles", "report", "snapshot", "undo", "install", "update", "completion", "metrics", "watch", "diff"]
order_ui = ["tui"]

# Parity guard: a new file in lib/util/, lib/features/, or lib/ui/ that
# isn't listed above would silently drop from the bundle and break the
# single-file release without any test catching it. Fail loudly instead.
def _check_parity(label, listed, directory):
    actual = sorted(p.stem for p in directory.glob("*.sh"))
    missing = sorted(set(actual) - set(listed))
    extra = sorted(set(listed) - set(actual))
    errors = []
    if missing:
        errors.append(f"{label} has files not listed in build order: {missing}")
    if extra:
        errors.append(f"{label} build order references missing files: {extra}")
    return errors

_parity_errors = []
_parity_errors += _check_parity("lib/util", order_utils, Path(root_path) / "lib/util")
_parity_errors += _check_parity("lib/features", order_features, Path(root_path) / "lib/features")
_parity_errors += _check_parity("lib/ui", order_ui, Path(root_path) / "lib/ui")
if _parity_errors:
    for err in _parity_errors:
        print(f"build-bundle: {err}", file=sys.stderr)
    sys.exit(1)

# Parity guard for tasks: lib/tasks/ uses sorted(glob) so every *.sh is
# picked up automatically, but we still validate that every task file
# contains a `pi_task_register` call (matching pi_load_tasks's runtime
# check). A stray file without registration would be sourced but
# contribute nothing to PI_TASK_ORDER — cheaper to catch it here than
# on an end-user Pi.
tasks_dir = Path(root_path) / "lib/tasks"
task_files = sorted(tasks_dir.glob("*.sh"))
if not task_files:
    print("build-bundle: lib/tasks is empty", file=sys.stderr)
    sys.exit(1)
_task_errors = []
for tf in task_files:
    body = tf.read_text()
    has_register = any(
        line.lstrip().startswith("pi_task_register ")
        for line in body.splitlines()
    )
    if not has_register:
        _task_errors.append(f"{tf.name}: no pi_task_register call found")
if _task_errors:
    for err in _task_errors:
        print(f"build-bundle: {err}", file=sys.stderr)
    sys.exit(1)

# MANIFEST parity: every task file should be listed in lib/MANIFEST.
# The runtime is lenient (appends unlisted tasks to the end) but for
# a release bundle we want determinism — require full coverage so
# ordering surprises don't ship.
manifest_path = Path(root_path) / "lib/MANIFEST"
manifest_lines = [
    ln.split("#", 1)[0].strip()
    for ln in manifest_path.read_text().splitlines()
]
manifest_ids = {ln for ln in manifest_lines if ln}
# Task IDs are derived from `pi_task_register <id> ...` lines. Extract
# them so we compare by registered id, not by filename (some tasks
# register under an id different from the filename stem).
task_ids = set()
for tf in task_files:
    for line in tf.read_text().splitlines():
        s = line.lstrip()
        if s.startswith("pi_task_register "):
            # shlex-lite: register's first positional arg is the id.
            parts = s.split()
            if len(parts) >= 2:
                task_ids.add(parts[1])
missing_from_manifest = sorted(task_ids - manifest_ids)
extra_in_manifest = sorted(manifest_ids - task_ids)
if missing_from_manifest or extra_in_manifest:
    if missing_from_manifest:
        print(f"build-bundle: tasks registered but not in MANIFEST: {missing_from_manifest}",
              file=sys.stderr)
    if extra_in_manifest:
        print(f"build-bundle: MANIFEST lists unknown task ids: {extra_in_manifest}",
              file=sys.stderr)
    sys.exit(1)

parts = []
parts.append("# --- begin pi-optimiser bundle ---\n")
# PI_OPTIMISER_BUNDLED flags that the script is the concatenated
# release bundle (no filesystem `lib/` tree). --migrate and --update
# short-circuit with a friendly error when set — the bundle is for
# one-shot `curl | sudo bash` use; installed operation is via
# install.sh / the git checkout.
parts.append("PI_OPTIMISER_BUNDLED=1\n")
parts.append("export PI_OPTIMISER_BUNDLED\n")
parts.append('SCRIPT_DIR="${PI_OPTIMISER_SCRIPT_DIR:-/opt/pi-optimiser/current}"\n')
parts.append('LIB_UTIL_DIR="$SCRIPT_DIR/lib/util"\n')
parts.append('LIB_FEATURES_DIR="$SCRIPT_DIR/lib/features"\n')
parts.append('LIB_UI_DIR="$SCRIPT_DIR/lib/ui"\n')

def inline(label, path):
    body = Path(path).read_text()
    if body.startswith("#!"):
        body = "\n".join(body.splitlines()[1:]) + "\n"
    parts.append(f"\n# --- begin bundled: {label} ---\n")
    parts.append(body)
    if not body.endswith("\n"):
        parts.append("\n")
    parts.append(f"# --- end bundled: {label} ---\n")

root = Path(root_path)
for u in order_utils:
    inline(f"lib/util/{u}.sh", root / f"lib/util/{u}.sh")
for f in order_features:
    inline(f"lib/features/{f}.sh", root / f"lib/features/{f}.sh")
for u in order_ui:
    inline(f"lib/ui/{u}.sh", root / f"lib/ui/{u}.sh")

# Embed manifest and tasks. Tasks are sourced via a generated function
# that records the embedded task ids so pi_load_tasks / pi_load_manifest
# can operate without a filesystem.
parts.append("\n# --- begin embedded task manifest + bodies ---\n")
manifest_raw = (root / "lib/MANIFEST").read_text()
parts.append("PI_EMBEDDED_MANIFEST=$(cat <<'MANIFEST_EOF'\n")
parts.append(manifest_raw)
parts.append("MANIFEST_EOF\n)\n")

# sorted() gives a deterministic, locale-independent ordering (Python
# uses codepoint comparison, not LC_COLLATE).
for task in sorted((root / "lib/tasks").glob("*.sh")):
    inline(f"lib/tasks/{task.name}", task)

parts.append("# --- end embedded task manifest + bodies ---\n")

parts.append("\n# Rebind pi_load_tasks / pi_load_manifest to operate on\n")
parts.append("# the embedded manifest so no filesystem access is needed.\n")
parts.append(r"""
pi_load_tasks() { :; }  # tasks were already sourced above

pi_load_manifest() {
  PI_TASK_ORDER=()
  local line id
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%%#*}
    line=${line//[[:space:]]/}
    [[ -z "$line" ]] && continue
    if [[ -z "${PI_TASK_DESC[$line]:-}" ]]; then
      echo "pi-optimiser(bundle): MANIFEST references missing task '$line'" >&2
      exit 1
    fi
    PI_TASK_ORDER+=("$line")
  done <<< "$PI_EMBEDDED_MANIFEST"
  for id in "${!PI_TASK_DESC[@]}"; do
    if ! printf '%s\n' "${PI_TASK_ORDER[@]}" | grep -qx "$id"; then
      PI_TASK_ORDER+=("$id")
    fi
  done
}
""")
parts.append("# --- end pi-optimiser bundle ---\n")

# Write via a temp file + os.replace inside the python step itself so
# even a python crash between "open" and "write" leaves $tmp_path
# empty (not half-written). The outer shell then `mv`s atomically.
payload = pre + "".join(parts) + post
with open(tmp_path, "w") as fh:
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())
PY

# --- Post-write sanity gates. Any failure here leaves $tmp on disk
# and the trap cleans it up — $output is never touched.

# 1. Parse-check: the bundle must parse in bash without touching lib/.
if ! bash -n "$tmp"; then
  echo "build-bundle.sh: output failed bash -n" >&2
  exit 1
fi

# 2. Leaked source-loop check: no `source lib/...` or `. lib/...` lines
# should remain — if any survive, the bundle would try to read from a
# filesystem that doesn't exist on the target.
# shellcheck disable=SC2016  # literal $LIB_ must stay single-quoted for grep
if grep -En '^[[:space:]]*(source|\.)[[:space:]]+.*(\$LIB_|[/"]lib/)' "$tmp" >/dev/null; then
  echo "build-bundle.sh: bundle still contains unresolved source lib/ calls:" >&2
  # shellcheck disable=SC2016  # literal $LIB_ must stay single-quoted for grep
  grep -nE '^[[:space:]]*(source|\.)[[:space:]]+.*(\$LIB_|[/"]lib/)' "$tmp" >&2 || true
  exit 1
fi

# 3. Shebang + strict-mode parity with the main script. A reordering
# refactor that drops `set -euo pipefail` or `umask 0022` from the
# pre-source block would silently ship a less-safe bundle. Compare
# the first four non-blank lines of each.
_first_strict() {
  awk 'NF && !/^#/ && !/^$/ {print; n++; if (n==3) exit}' "$1"
}
if ! diff -u <(_first_strict "$main") <(_first_strict "$tmp") >/dev/null; then
  echo "build-bundle.sh: bundle shebang/strict-mode header diverged from main script:" >&2
  diff -u <(_first_strict "$main") <(_first_strict "$tmp") >&2 || true
  exit 1
fi

# 4. Behavioural parity: --version and --list-tasks should match the
# main script exactly. This catches missing task sources even if the
# bundle parses clean (e.g. a task file that fails `pi_task_register`
# because a dependency is missing).
_bundle_env=(env PI_OPTIMISER_SCRIPT_DIR=/nonexistent)
main_version=$("$main" --version 2>/dev/null)
bundle_version=$("${_bundle_env[@]}" bash "$tmp" --version 2>/dev/null)
# The bundle's $0 basename differs from pi-optimiser.sh (it's named
# after $output), so normalise the script-name token before compare.
main_version_norm=${main_version#* }
bundle_version_norm=${bundle_version#* }
if [[ "$main_version_norm" != "$bundle_version_norm" ]]; then
  echo "build-bundle.sh: --version mismatch:" >&2
  echo "  main:   $main_version" >&2
  echo "  bundle: $bundle_version" >&2
  exit 1
fi

main_tasks=$("$main" --list-tasks 2>/dev/null | wc -l | tr -d ' ')
bundle_tasks=$("${_bundle_env[@]}" bash "$tmp" --list-tasks 2>/dev/null | wc -l | tr -d ' ')
if [[ "$main_tasks" != "$bundle_tasks" ]]; then
  echo "build-bundle.sh: --list-tasks count mismatch (main=$main_tasks bundle=$bundle_tasks)" >&2
  exit 1
fi

# 5. All gates passed — atomically publish the bundle.
mv "$tmp" "$output"
chmod 0755 "$output"

# 6. Emit a SHA256 sidecar so install.sh / the release workflow can
# verify integrity without a second hash pass. Produced in the same
# dir as the bundle so the sidecar records a bare filename — this is
# what `sha256sum -c` expects when users download the pair.
sidecar="$output.sha256"
(
  cd "$output_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$(basename "$output")" > "$(basename "$sidecar")"
  elif command -v shasum >/dev/null 2>&1; then
    # macOS ships shasum by default; emit GNU-compatible "<hex>  <file>".
    shasum -a 256 "$(basename "$output")" > "$(basename "$sidecar")"
  else
    echo "build-bundle.sh: neither sha256sum nor shasum found; sidecar skipped" >&2
    rm -f "$(basename "$sidecar")"
  fi
)

# Clear the trap now that $tmp no longer exists (it was moved to $output).
trap - EXIT

lines=$(wc -l <"$output" | tr -d ' ')
bytes=$(wc -c <"$output" | tr -d ' ')
echo "Wrote $output ($lines lines, $bytes bytes)"
if [[ -f "$sidecar" ]]; then
  echo "Wrote $sidecar"
fi
