# ======================================================================
# lib/features/install.sh — installed-layout maintenance
#
# Functions: pi_uninstall, pi_migrate_install, pi_rollback_release
#
# Install layout (created by install.sh):
#   /opt/pi-optimiser/
#     current -> releases/<id>/
#     releases/<id>/        (pi-optimiser.sh + lib/*)
#   /usr/local/sbin/pi-optimiser (symlink)
#
# User state (/etc/pi-optimiser/*, /var/log/pi-optimiser.log) is never
# touched by these commands — they only manage the code tree.
# ======================================================================

PI_LAUNCHER_SYMLINK="${PI_OPTIMISER_BIN:-/usr/local/sbin/pi-optimiser}"

# Remove the install prefix and launcher symlink. Leaves state + logs.
pi_uninstall() {
  if [[ ${DRY_RUN:-0} -eq 1 ]]; then
    log_info "[dry-run] would remove $PI_PREFIX and $PI_LAUNCHER_SYMLINK (state preserved)"
    return 0
  fi
  if [[ ${PI_NON_INTERACTIVE:-0} -ne 1 ]]; then
    echo "About to remove $PI_PREFIX and $PI_LAUNCHER_SYMLINK."
    echo "/etc/pi-optimiser/* and /var/log/pi-optimiser.log are preserved."
    echo "Pass --yes to skip this prompt."
    read -r -p "Continue? [y/N] " answer </dev/tty
    case ${answer,,} in
      y|yes) ;;
      *) log_warn "Uninstall cancelled"; return 0 ;;
    esac
  fi
  if [[ -L "$PI_LAUNCHER_SYMLINK" || -f "$PI_LAUNCHER_SYMLINK" ]]; then
    rm -f "$PI_LAUNCHER_SYMLINK"
    log_info "Removed launcher symlink $PI_LAUNCHER_SYMLINK"
  fi
  if [[ -d "$PI_PREFIX" ]]; then
    rm -rf "$PI_PREFIX"
    log_info "Removed install tree $PI_PREFIX"
  fi
  log_info "Uninstall complete. State retained at /etc/pi-optimiser/"
}

# Copy the currently-running checkout to $PI_PREFIX as a new release,
# then flip the `current` symlink and drop the launcher symlink.
pi_migrate_install() {
  if [[ ${PI_OPTIMISER_BUNDLED:-0} -eq 1 ]]; then
    log_error "--migrate isn't meaningful on a single-file bundle."
    log_error "Run install.sh or clone the repo for an installed layout."
    return 1
  fi
  if [[ ${DRY_RUN:-0} -eq 1 ]]; then
    log_info "[dry-run] would stage $SCRIPT_DIR into $PI_PREFIX/releases/migrated-<ts>"
    return 0
  fi
  local ts release_dir
  ts=$(date +%Y%m%d%H%M%S)
  release_dir="$PI_PREFIX/releases/migrated-$ts"
  mkdir -p "$release_dir"
  chmod 755 "$PI_PREFIX" "$PI_PREFIX/releases"
  local item
  for item in pi-optimiser.sh lib scripts share README.md AGENTS.md LICENSE SECURITY.md; do
    if [[ -e "$SCRIPT_DIR/$item" ]]; then
      cp -a "$SCRIPT_DIR/$item" "$release_dir/"
    fi
  done
  chmod +x "$release_dir/pi-optimiser.sh" 2>/dev/null || true

  # Drop logrotate config if shipped in share/.
  if [[ -f "$release_dir/share/logrotate/pi-optimiser" ]]; then
    install -m 0644 "$release_dir/share/logrotate/pi-optimiser" \
      /etc/logrotate.d/pi-optimiser 2>/dev/null || true
  fi
  # Bash completion.
  if [[ -d /etc/bash_completion.d && -x "$release_dir/pi-optimiser.sh" ]]; then
    "$release_dir/pi-optimiser.sh" --completion bash \
      > /etc/bash_completion.d/pi-optimiser 2>/dev/null \
      || rm -f /etc/bash_completion.d/pi-optimiser
  fi
  # Man page (only if pandoc is available).
  if command -v pandoc >/dev/null 2>&1 \
      && [[ -f "$release_dir/share/man/pi-optimiser.8.md" ]]; then
    mkdir -p /usr/local/share/man/man8
    pandoc -s -t man "$release_dir/share/man/pi-optimiser.8.md" \
      | gzip -9 > /usr/local/share/man/man8/pi-optimiser.8.gz 2>/dev/null \
      || rm -f /usr/local/share/man/man8/pi-optimiser.8.gz
  fi

  ln -sfn "$release_dir" "$PI_PREFIX/current.new"
  mv -Tf "$PI_PREFIX/current.new" "$PI_PREFIX/current"
  mkdir -p "$(dirname "$PI_LAUNCHER_SYMLINK")"
  ln -sf "$PI_PREFIX/current/pi-optimiser.sh" "$PI_LAUNCHER_SYMLINK"
  log_info "Migrated checkout to $release_dir"
  log_info "Launcher: $PI_LAUNCHER_SYMLINK -> $release_dir/pi-optimiser.sh"
}

# Flip `current` to the second-most-recent release, if one exists.
pi_rollback_release() {
  if [[ ${DRY_RUN:-0} -eq 1 ]]; then
    log_info "[dry-run] would flip $PI_PREFIX/current back to the previous release"
    return 0
  fi
  local releases="$PI_PREFIX/releases"
  if [[ ! -d "$releases" ]]; then
    log_error "No releases directory at $releases; nothing to roll back to"
    return 1
  fi
  local current_target previous
  if [[ -L "$PI_PREFIX/current" ]]; then
    current_target=$(readlink -f "$PI_PREFIX/current")
  fi
  # Pick the newest release that isn't the current target.
  mapfile -t candidates < <(ls -1t "$releases" 2>/dev/null)
  local entry
  for entry in "${candidates[@]}"; do
    if [[ "$releases/$entry" != "$current_target" ]]; then
      previous="$releases/$entry"
      break
    fi
  done
  if [[ -z "${previous:-}" ]]; then
    log_error "No previous release found under $releases"
    return 1
  fi
  ln -sfn "$previous" "$PI_PREFIX/current.new"
  mv -Tf "$PI_PREFIX/current.new" "$PI_PREFIX/current"
  log_info "Rolled back to $previous"
}
