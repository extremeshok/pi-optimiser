# TODO — deferred items

Tracked here so new contributors can pick them up without another
audit pass surfacing the same thing. Organised by effort.

## Must happen next

- **Interactive TUI walk-through.** The whiptail UI has been
  structurally verified (boot, source, profile suggester, non-TTY
  suppression) but never driven through every screen on a real
  terminal. Expected outputs:
  - Welcome → profile suggestion → profile applied
  - Main menu reachable; each category checklist toggles correctly
  - Input forms accept valid input and reject invalid (regex)
  - Apply → config saved, tasks dispatched, progress shown
  - Status screen renders without clipping at 24×80
  - Exit is clean (no stale tty state)

- **`install.sh | sudo bash` from a tagged release.** The installer
  is tested via the local `--migrate` path; it needs a dry run from
  the real GitHub URL after `v9.0.1` is tagged (and `release.yml`
  has attached the bundle).

## Small (one session each)

- **Surface reboot-required in `--report` and the post-run summary.**
  `boot_config`, `libliftoff`, `oc_conservative`, `underclock`,
  `pi5_fan`, `pcie_gen3`, `thermal_thresholds`, `watchdog`,
  `eeprom_config`, `firmware_update`, `eeprom_refresh`, and
  `docker --docker-cgroupv2` all mutate settings that only take
  effect after a reboot. Add a `pi_mark_reboot_required` helper
  that writes `reboot_required: true` to `CONFIG_OPTIMISER_STATE`
  and have the summary + `--report` flag it prominently.

- **Shell completion.** `pi-optimiser --completion bash` should
  emit a simple completion generator dropped to
  `/etc/bash_completion.d/pi-optimiser`:
  ```
  complete -W "$(pi-optimiser --list-tasks | awk 'NR>2 {print $1}')" \
    pi-optimiser
  ```
  Add a `--completion {bash,zsh}` flag; wire into the installer.

- **Man page.** Convert the `usage()` text into
  `share/man/pi-optimiser.8.md`, process with pandoc, ship the
  gzipped `.8` under `share/man/`, and have the installer drop it
  to `/usr/local/share/man/man8/`.

- **YAML parser: tolerate trailing `# inline comments`.** Current
  parser only strips whole-line comments. A config with
  `hostname: pi-kiosk  # behind the desk` stores the comment as
  part of the value.

- **TUI `TERM=dumb` guard.** `pi_tui_available` currently only
  checks `command -v whiptail`. With `TERM=dumb`, whiptail renders
  garbage. Add `[[ "${TERM:-dumb}" == "dumb" ]] && return 1`.

- **JSON output schema docs.** Ship
  `docs/status.schema.json` and `docs/report.schema.json` so
  consumers of `--output json` can validate. The shapes are stable
  (they're tested); the files just need writing.

- **`--undo` after `--restore` invalidates stale journals.**
  `--restore` overwrites files without clearing
  `/etc/pi-optimiser/backups/*.json`, so a later `--undo` restores
  from pre-restore backups, effectively undoing the restore. Fix:
  rename `backups/` to `backups.pre-restore-<ts>/` during restore.

- **`PI_OPTIMISER_BUNDLED` is dead.** The bundle sets it but
  nothing reads it. Either wire it to skip operations that don't
  make sense from a single-file bundle (`--migrate`, `--update`),
  or remove the variable.

## Medium (a session or two)

- **Self-update signing infrastructure.** The verifier
  (`pi_update_verify_signature` in `lib/features/update.sh`)
  supports minisign. What's missing:
  - Key-publishing workflow (where does the public key live?
    `share/keys/pi-optimiser.pub` shipped in each release?)
  - CI release step that signs `pi-optimiser-<tag>.sh` with a
    project key held offline.
  - Flip `--require-signature` to **default on** once signing is
    operational.

- **Unified-diff dry-run for config.txt / cmdline.txt edits.**
  The `ensure_config_key_value` helper would need a diff-buffering
  mode that accumulates proposed writes and prints a unified diff
  at the end. Touches every config-editing task.

- **Per-task version pinning.** `--pin-task <id>=<version>`
  (fetch a historical task from a tag archive) and
  `--freeze-task <id>` (never update). Not a correctness need, but
  useful when a single task regresses on a specific hardware
  generation. Requires a per-task version manifest fetched from
  the same repo.

- **`--show-config` and `--dry-run --diff`.** Dump the effective
  config (after CLI + YAML + defaults) for troubleshooting.

- **`--undo --all`.** Roll back every task completed in the most
  recent run in reverse order. Requires cross-task run-grouping
  in the backup journals (the `run_id` is already recorded).

## Low (nice to have)

- **Reboot timer.** `--reboot-when-done` / `--reboot-after 5min`
  for one-shot deployments.
- **Prometheus metrics export** via node-exporter's textfile
  collector (count completed/failed/skipped per task, last-run
  timestamp).
- **`--watch`** mode: re-run on config.yaml changes via `inotify`.
- **Dockerised test harness** for CI: a Debian Trixie container
  with stubbed `vcgencmd` / `rpi-eeprom-config` / `rpi-update` so
  more of the code paths run under CI than just `shellcheck`.
- **`--self-test`** that runs a read-only subset of every task's
  precondition checks (no mutations) to verify the system meets
  each task's requirements.

## Resolved in 9.0.1 (removed from this list)

All CRIT and HIGH items from the second-pass audit. See
`CHANGELOG.md` for the full list.
