# ======================================================================
# lib/features/snapshot.sh — pre-run config snapshot + restore
#
# Functions: pi_take_snapshot, pi_restore_snapshot
#
# --snapshot  tars a curated list of paths into
#             /etc/pi-optimiser/snapshots/<YYYYMMDDHHMMSS>.tgz and exits.
#
# --restore <path>  untars a snapshot into / after a confirmation
#                   (suppressed by --yes / --non-interactive).
# ======================================================================

PI_SNAPSHOT_DIR="/etc/pi-optimiser/snapshots"

# Paths included in a snapshot. Directories are traversed; missing
# entries are silently skipped.
declare -a PI_SNAPSHOT_PATHS=(
  /etc/fstab
  /etc/hosts
  /etc/hostname
  /etc/timezone
  /etc/default/locale
  /etc/localtime
  /etc/ssh/sshd_config
  /etc/ssh/sshd_config.d
  /etc/nginx/sites-available
  /etc/nginx/sites-enabled
  /etc/sysctl.d
  /etc/security/limits.d
  /etc/systemd/journald.conf.d
  /etc/systemd/system.conf.d
  /etc/systemd/user.conf.d
  /etc/systemd/zram-generator.conf
  /etc/tmpfiles.d/pi-optimiser-varlog.conf
  /etc/apt/apt.conf.d/20pi-optimiser
  /etc/apt/apt.conf.d/51pi-optimiser-unattended.conf
  /etc/apt/sources.list.d/tailscale.list
  /etc/apt/sources.list.d/docker.list
  /etc/pi-optimiser
  /boot/firmware/config.txt
  /boot/firmware/cmdline.txt
)

pi_take_snapshot() {
  if [[ ${DRY_RUN:-0} -eq 1 ]]; then
    log_info "[dry-run] would snapshot ${#PI_SNAPSHOT_PATHS[@]} paths to $PI_SNAPSHOT_DIR"
    return 0
  fi
  mkdir -p "$PI_SNAPSHOT_DIR"
  chmod 700 "$PI_SNAPSHOT_DIR"
  local ts archive
  ts=$(date +%Y%m%d%H%M%S)
  archive="$PI_SNAPSHOT_DIR/$ts.tgz"

  local -a existing=()
  local p
  for p in "${PI_SNAPSHOT_PATHS[@]}"; do
    [[ -e "$p" ]] && existing+=("$p")
  done
  if (( ${#existing[@]} == 0 )); then
    log_warn "No snapshot sources found; aborting"
    return 1
  fi

  log_info "Snapshotting ${#existing[@]} paths to $archive"
  # Store as RELATIVE paths (tar -P strips the leading /, which is the
  # default for GNU tar without -P or --absolute-names). On restore we
  # extract against / so the effective destination is the same, but
  # the archive itself can be safely untarred into a staging directory
  # first for inspection without risking system writes.
  # Exclude our own snapshots/backups/state dirs to avoid self-recursion.
  if tar -czf "$archive" \
       --exclude="$PI_SNAPSHOT_DIR" \
       --exclude="$MARKER_DIR/backups" \
       --exclude="$MARKER_DIR/state.json" \
       --exclude="$MARKER_DIR/state.schema" \
       --exclude="$MARKER_DIR/state" \
       "${existing[@]}" 2>/dev/null; then
    chmod 600 "$archive"
    log_info "Snapshot written: $archive ($(stat -c%s "$archive") bytes)"
    printf '%s\n' "$archive"
    return 0
  fi
  log_error "Snapshot failed"
  return 1
}

pi_restore_snapshot() {
  local archive=$1
  if [[ ! -f "$archive" ]]; then
    log_error "Snapshot file not found: $archive"
    return 1
  fi
  if [[ ! -s "$archive" ]] || ! tar -tzf "$archive" >/dev/null 2>&1; then
    log_error "Snapshot file is empty or corrupt: $archive"
    return 1
  fi
  if [[ ${DRY_RUN:-0} -eq 1 ]]; then
    log_info "[dry-run] would restore $archive to /"
    tar -tzf "$archive" 2>/dev/null | head -10 | sed 's/^/[dry-run]   /'
    return 0
  fi
  if [[ ${PI_NON_INTERACTIVE:-0} -ne 1 ]]; then
    echo "About to overwrite system config from: $archive"
    echo "This will touch /etc/* and /boot/firmware/* entries from the snapshot."
    echo "Pass --yes to skip this prompt."
    read -r -p "Continue? [y/N] " answer </dev/tty
    case ${answer,,} in
      y|yes) ;;
      *) log_warn "Restore cancelled"; return 0 ;;
    esac
  fi
  local stage
  stage=$(mktemp -d)
  # Expand $stage now (it's known at trap-setup time) so the RETURN
  # handler can clean up; shellcheck SC2064 is the cautious default.
  # shellcheck disable=SC2064
  trap "rm -rf '$stage'" RETURN

  # Defensive pre-scan: reject any archive containing entries that
  # would escape root on extraction (absolute paths or .. traversal).
  # GNU tar also enforces this on extract by default, but an explicit
  # check produces a better error message and prevents partial writes.
  local bad
  bad=$(tar -tzf "$archive" 2>/dev/null | grep -nE '^(/|(\./)?\.\./|.*/\.\./)' | head -n 1)
  if [[ -n "$bad" ]]; then
    log_error "Snapshot contains unsafe path: $bad"
    return 1
  fi
  # Check for symlinks whose target escapes the archive's directory
  # tree. `tar -tvzf` listing includes symlink targets in the form
  # `foo -> /etc/shadow`; we reject any absolute or .. target.
  bad=$(tar -tvzf "$archive" 2>/dev/null | awk '/->/ { for(i=1;i<=NF;i++) if($i=="->"){print $(i+1); break} }' \
        | grep -E '^(/|.*/\.\./|\.\./)' | head -n 1)
  if [[ -n "$bad" ]]; then
    log_error "Snapshot contains symlink pointing outside archive: $bad"
    return 1
  fi

  log_info "Extracting snapshot onto the live filesystem"
  # --no-same-owner prevents chown forgery; --no-absolute-names is a
  # belt on top of the pre-scan since GNU tar already strips leading /;
  # --no-overwrite-dir keeps existing dirs' modes rather than restoring
  # them from the archive (harmless for our own snapshots).
  if ! tar -xzf "$archive" -C / \
        --no-same-owner \
        --no-absolute-names \
        --no-overwrite-dir 2>/dev/null; then
    log_error "Snapshot extraction failed"
    return 1
  fi
  log_info "Snapshot restore complete. Some changes require a reboot."
}
