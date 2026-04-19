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
# ======================================================================
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:-"$root/dist/pi-optimiser-bundle.sh"}
mkdir -p "$(dirname "$output")"

main="$root/pi-optimiser.sh"
if [[ ! -f "$main" ]]; then
  echo "build-bundle.sh: cannot find $main" >&2
  exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

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

order_utils = ["log", "python", "state", "backup", "config_txt", "cmdline",
               "fstab", "sshd", "apt", "systemd", "model", "hardware",
               "preflight", "validate", "config_yaml"]
order_features = ["profiles", "report", "snapshot", "undo", "install", "update"]
order_ui = ["tui"]

parts = []
parts.append("# --- begin pi-optimiser bundle ---\n")
parts.append("PI_OPTIMISER_BUNDLED=1\n")
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

with open(tmp_path, "w") as fh:
    fh.write(pre)
    fh.write("".join(parts))
    fh.write(post)
PY

mv "$tmp" "$output"
chmod +x "$output"

# Fast sanity: the bundle must parse in bash without touching lib/.
if ! bash -n "$output"; then
  echo "build-bundle.sh: output failed bash -n" >&2
  exit 1
fi

lines=$(wc -l <"$output")
bytes=$(wc -c <"$output")
echo "Wrote $output ($lines lines, $bytes bytes)"
