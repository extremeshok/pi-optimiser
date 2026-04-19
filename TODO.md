# TODO — deferred items

Tracked here so new contributors can pick them up without another
audit pass surfacing the same thing. Organised by effort.

## Must happen next

- **Interactive TUI walk-through.** The whiptail UI has been
  structurally verified (boot, source, profile suggester, non-TTY
  suppression, `TERM=dumb` guard). It has not been driven through
  every screen on a real terminal. Requires a human + a display.
  Expected outputs:
  - Welcome → profile suggestion → profile applied
  - Main menu reachable; each category checklist toggles correctly
  - Input forms accept valid input and reject invalid (regex)
  - Apply → config saved, tasks dispatched, progress shown
  - Status screen renders without clipping at 24×80
  - Exit is clean (no stale tty state)

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

## Low (nice to have)

- **Prometheus metrics export** via node-exporter's textfile
  collector (count completed/failed/skipped per task, last-run
  timestamp).
- **`--watch`** mode: re-run on config.yaml changes via `inotify`.
- **Dockerised test harness** for CI: a Debian Trixie container
  with stubbed `vcgencmd` / `rpi-eeprom-config` / `rpi-update` so
  more of the code paths run under CI than just `shellcheck`.

## Resolved (see CHANGELOG.md)

- **9.0.2**: reboot-required surfacing, YAML inline comments,
  stricter `--validate-config`, `--completion`, `--show-config`,
  `--undo --all`, `--self-test`, `--reboot-after`, man page,
  JSON schema docs, `TERM=dumb` guard, bundle-mode guards on
  `--migrate` and `--update`, stale-journal rotation on
  `--restore`, `install.sh` cleaner 404 path.
- **9.0.1**: 3 CRITs + 10 HIGHs + 10 MEDs from audit pass #2.
  See `CHANGELOG.md` for the full list.
- **9.0.0**: modular refactor, self-update, TUI, installer.
