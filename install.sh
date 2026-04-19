#!/usr/bin/env bash
# ======================================================================
# pi-optimiser bootstrap / installer
# ======================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/extremeshok/pi-optimiser/master/install.sh | sudo bash
#
# Environment knobs:
#   PI_OPTIMISER_REF     git ref to install (default: master)
#   PI_OPTIMISER_PREFIX  install prefix (default: /opt/pi-optimiser)
#   PI_OPTIMISER_BIN     symlink path    (default: /usr/local/sbin/pi-optimiser)
#
# This installer is intentionally small and rarely changes. It:
#   1. Downloads the tree at the requested ref via the GitHub tarball.
#   2. Stages it under $PREFIX/releases/<ref>-<ts>/.
#   3. Atomically flips $PREFIX/current to the new release.
#   4. Symlinks $BIN → $PREFIX/current/pi-optimiser.sh.
#   5. Retains the previous release for --rollback.
# ======================================================================
set -euo pipefail

PI_OPTIMISER_REF="${PI_OPTIMISER_REF:-master}"
PI_OPTIMISER_PREFIX="${PI_OPTIMISER_PREFIX:-/opt/pi-optimiser}"
PI_OPTIMISER_BIN="${PI_OPTIMISER_BIN:-/usr/local/sbin/pi-optimiser}"
PI_OPTIMISER_REPO="${PI_OPTIMISER_REPO:-extremeshok/pi-optimiser}"
PI_OPTIMISER_KEEP="${PI_OPTIMISER_KEEP:-2}"

if [[ $EUID -ne 0 ]]; then
  echo "install.sh must be run as root (e.g. with sudo)." >&2
  exit 1
fi

for dep in curl tar; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "install.sh requires '$dep' to be installed." >&2
    exit 1
  fi
done

ts=$(date +%Y%m%d%H%M%S)
release_id="${PI_OPTIMISER_REF//\//-}-${ts}"
release_dir="$PI_OPTIMISER_PREFIX/releases/$release_id"
releases_root="$PI_OPTIMISER_PREFIX/releases"

mkdir -p "$releases_root"
chmod 755 "$PI_OPTIMISER_PREFIX" "$releases_root"

tmp_tar=$(mktemp)
tmp_extract=$(mktemp -d)
trap 'rm -f "$tmp_tar"; rm -rf "$tmp_extract"' EXIT

tarball_url="https://codeload.github.com/${PI_OPTIMISER_REPO}/tar.gz/refs/heads/${PI_OPTIMISER_REF}"
echo "Fetching pi-optimiser @ ${PI_OPTIMISER_REF}"
if ! curl -fsSL "$tarball_url" -o "$tmp_tar"; then
  # Fall back to tag path.
  tarball_url="https://codeload.github.com/${PI_OPTIMISER_REPO}/tar.gz/refs/tags/${PI_OPTIMISER_REF}"
  if ! curl -fsSL "$tarball_url" -o "$tmp_tar"; then
    echo "Failed to download ${tarball_url}" >&2
    exit 1
  fi
fi

echo "Extracting…"
tar -xzf "$tmp_tar" -C "$tmp_extract"
# GitHub tars unpack as <repo>-<ref>/...
src_root=$(find "$tmp_extract" -maxdepth 1 -mindepth 1 -type d | head -n1)
if [[ -z "$src_root" ]]; then
  echo "Unexpected tarball layout (no single top-level dir)" >&2
  exit 1
fi

mkdir -p "$release_dir"
# Copy only the files the runtime needs; skip CI, docs, and release
# bundles since they bloat the install.
for item in pi-optimiser.sh lib scripts README.md AGENTS.md LICENSE SECURITY.md; do
  if [[ -e "$src_root/$item" ]]; then
    cp -a "$src_root/$item" "$release_dir/"
  fi
done

chmod 755 "$release_dir"
chmod +x "$release_dir/pi-optimiser.sh"

# Atomic swap of the "current" symlink.
ln -sfn "$release_dir" "$PI_OPTIMISER_PREFIX/current.new"
mv -Tf "$PI_OPTIMISER_PREFIX/current.new" "$PI_OPTIMISER_PREFIX/current"

# Drop the launcher symlink.
mkdir -p "$(dirname "$PI_OPTIMISER_BIN")"
ln -sf "$PI_OPTIMISER_PREFIX/current/pi-optimiser.sh" "$PI_OPTIMISER_BIN"

# Retention: keep the N newest releases, drop older ones.
if [[ "$PI_OPTIMISER_KEEP" =~ ^[0-9]+$ ]] && (( PI_OPTIMISER_KEEP > 0 )); then
  mapfile -t releases < <(ls -1t "$releases_root" 2>/dev/null)
  if (( ${#releases[@]} > PI_OPTIMISER_KEEP )); then
    for stale in "${releases[@]:$PI_OPTIMISER_KEEP}"; do
      [[ -z "$stale" ]] && continue
      rm -rf "${releases_root:?}/${stale:?}"
    done
  fi
fi

echo "Installed to: $release_dir"
echo "Launcher:     $PI_OPTIMISER_BIN"
echo
echo "Next step: run 'sudo pi-optimiser --help' or 'sudo pi-optimiser --list-tasks'"
