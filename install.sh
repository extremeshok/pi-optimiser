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
# Strict umask for a root-run installer: every file we drop under
# /opt/pi-optimiser/releases/, /etc/logrotate.d/, /etc/bash_completion.d/
# and /usr/local/share/man/ should be 0644/0755. A permissive umask
# (0000) inherited from a weird `sudo` setup would leak world-writable
# system files. Pin 0022 up-front.
umask 0022

# Harden the bootstrap environment: avoid inherited PATH / curl / git
# overrides from subverting our download or extraction path. Drop any
# GIT_*, CURL_*, SSL_CERT_*, *_PROXY that could redirect traffic or
# point at an attacker-controlled CA. We explicitly reset PATH to the
# standard system dirs.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset IFS
for _var in $(env 2>/dev/null | awk -F= '/^(GIT_|CURL_|SSL_CERT_|TLS_)/ {print $1}'); do
  unset "$_var" 2>/dev/null || true
done
# Don't clobber proxies set intentionally by the operator, but warn if
# they exist so interactive operators know what they're trusting.
for _var in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
  if [[ -n "${!_var:-}" ]]; then
    echo "install.sh: note: $_var is set (${!_var}); downloads will use it" >&2
  fi
done

PI_OPTIMISER_REF="${PI_OPTIMISER_REF:-master}"
PI_OPTIMISER_PREFIX="${PI_OPTIMISER_PREFIX:-/opt/pi-optimiser}"
PI_OPTIMISER_BIN="${PI_OPTIMISER_BIN:-/usr/local/sbin/pi-optimiser}"
PI_OPTIMISER_REPO="${PI_OPTIMISER_REPO:-extremeshok/pi-optimiser}"
PI_OPTIMISER_KEEP="${PI_OPTIMISER_KEEP:-2}"

# curl flags: fail-fast, silent progress, show errors, follow HTTPS
# redirects up to a bounded depth, honor both connect and overall
# timeouts, reject plaintext redirects. --proto =https,http forbids
# file:// and other schemes from a redirect chain; --proto-redir =https
# forbids an HTTPS URL from being downgraded to HTTP mid-chain.
CURL_SECURE_OPTS=(
  --fail --silent --show-error --location
  --proto '=https' --proto-redir '=https'
  --max-redirs 5
  --connect-timeout 15 --max-time 300
  --tlsv1.2
  --retry 3 --retry-delay 2 --retry-connrefused
)

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

# install -d sets mode atomically with creation, avoiding the brief
# window where a freshly-mkdir'd directory has the umask-derived mode.
install -d -m 0755 "$PI_OPTIMISER_PREFIX"
install -d -m 0755 "$releases_root"

tmp_tar=$(mktemp)
tmp_extract=$(mktemp -d)
trap 'rm -f "$tmp_tar"; rm -rf "$tmp_extract"' EXIT

echo "Fetching pi-optimiser @ ${PI_OPTIMISER_REF}"
# Try tag first (the common case for versioned refs like v9.0.1), then
# fall back to branches (for master/main). `curl -fsSL -o` emits its
# own message on failure, so we route both attempts' stderr to /dev/null
# and only surface a combined error if both fail.
tag_url="https://codeload.github.com/${PI_OPTIMISER_REPO}/tar.gz/refs/tags/${PI_OPTIMISER_REF}"
branch_url="https://codeload.github.com/${PI_OPTIMISER_REPO}/tar.gz/refs/heads/${PI_OPTIMISER_REF}"
if ! curl "${CURL_SECURE_OPTS[@]}" "$tag_url" -o "$tmp_tar" 2>/dev/null; then
  if ! curl "${CURL_SECURE_OPTS[@]}" "$branch_url" -o "$tmp_tar" 2>/dev/null; then
    echo "Failed to download ${PI_OPTIMISER_REF} (tried tag + branch)" >&2
    exit 1
  fi
fi

# If the ref is an exact version tag (vX.Y.Z), attempt to fetch and
# verify the published release bundle sha256 alongside the tarball.
# This only protects version-tag installs, not master HEAD (no release
# artifact exists for a moving branch). Absence of a checksum file is
# not fatal — keep the current best-effort posture, but warn clearly.
if [[ "$PI_OPTIMISER_REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  checksum_url="https://github.com/${PI_OPTIMISER_REPO}/releases/download/${PI_OPTIMISER_REF}/pi-optimiser-${PI_OPTIMISER_REF}.sh.sha256"
  bundle_url="https://github.com/${PI_OPTIMISER_REPO}/releases/download/${PI_OPTIMISER_REF}/pi-optimiser-${PI_OPTIMISER_REF}.sh"
  tmp_sha=$(mktemp)
  tmp_bundle=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f \"$tmp_tar\" \"$tmp_sha\" \"$tmp_bundle\"; rm -rf \"$tmp_extract\"" EXIT
  if curl "${CURL_SECURE_OPTS[@]}" "$checksum_url" -o "$tmp_sha" 2>/dev/null \
     && curl "${CURL_SECURE_OPTS[@]}" "$bundle_url" -o "$tmp_bundle" 2>/dev/null; then
    if command -v sha256sum >/dev/null 2>&1; then
      expected=$(awk '{print $1}' "$tmp_sha")
      actual=$(sha256sum "$tmp_bundle" | awk '{print $1}')
      if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        echo "install.sh: SHA-256 mismatch for $bundle_url" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
      fi
      echo "Verified release bundle SHA-256 (${actual:0:12}…)"
    else
      echo "install.sh: sha256sum not available; skipping bundle verification" >&2
    fi
  else
    echo "install.sh: no release artefact / checksum found for ${PI_OPTIMISER_REF}; using tarball only (no integrity check)" >&2
  fi
  rm -f "$tmp_sha" "$tmp_bundle"
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
for item in pi-optimiser.sh lib scripts share README.md AGENTS.md LICENSE SECURITY.md; do
  if [[ -e "$src_root/$item" ]]; then
    cp -a "$src_root/$item" "$release_dir/"
  fi
done

# Drop logrotate config so /var/log/pi-optimiser.log doesn't grow
# unbounded. Idempotent; the file's small and owned by this package.
if [[ -f "$release_dir/share/logrotate/pi-optimiser" ]]; then
  install -m 0644 "$release_dir/share/logrotate/pi-optimiser" \
    /etc/logrotate.d/pi-optimiser 2>/dev/null || true
fi

# Bash completion — harmless if no bash-completion package is present
# (the file just sits there). Zsh users can source manually.
if [[ -d /etc/bash_completion.d ]] && [[ -x "$release_dir/pi-optimiser.sh" ]]; then
  "$release_dir/pi-optimiser.sh" --completion bash \
    > /etc/bash_completion.d/pi-optimiser 2>/dev/null \
    || rm -f /etc/bash_completion.d/pi-optimiser
fi

# Man page — only if pandoc is installed. Skipped silently otherwise
# (the shipped markdown source is still readable).
if command -v pandoc >/dev/null 2>&1 \
    && [[ -f "$release_dir/share/man/pi-optimiser.8.md" ]]; then
  mkdir -p /usr/local/share/man/man8
  pandoc -s -t man "$release_dir/share/man/pi-optimiser.8.md" \
    | gzip -9 > /usr/local/share/man/man8/pi-optimiser.8.gz 2>/dev/null \
    || rm -f /usr/local/share/man/man8/pi-optimiser.8.gz
fi

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
