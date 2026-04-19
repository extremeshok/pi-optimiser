# Changelog

## 9.1.0 — 2026-04-19

Feature batch closing out the post-9.0 TODO list: Prometheus textfile
metrics, config-watch mode, config.txt / cmdline.txt diff-preview,
per-task freeze, and a Dockerised integration-test harness. No
existing flag semantics changed; every new surface is opt-in.

### Added
- **Prometheus textfile-collector metrics**
  ([lib/features/metrics.sh](lib/features/metrics.sh)). After every
  run, pi-optimiser writes `/var/lib/node_exporter/textfile_collector/
  pi-optimiser.prom` (if the directory exists) or falls back to
  `/etc/pi-optimiser/metrics/pi-optimiser.prom`. Emits per-task
  status, completed/failed/skipped totals, last-run timestamp,
  reboot-required gauge, and a version-info label. Disable with
  `--no-metrics` or `metrics.enabled: false` in config.yaml; override
  the path with `--metrics-path <path>` or `metrics.path: <path>`.
- **`--watch` mode** ([lib/features/watch.sh](lib/features/watch.sh)).
  After the initial run, block on `inotifywait` against config.yaml
  and re-exec on change. Falls back to a 10-second polling loop when
  `inotify-tools` is absent (warning emitted so the user can
  `apt install inotify-tools`). A 2 s debounce collapses burst events
  from editor save-temp renames. Task failures under `--watch` don't
  kill the watcher.
- **`--diff` preview mode**
  ([lib/features/diff.sh](lib/features/diff.sh)). Invokes each
  config-editing task's `pi_preview_<id>` callback instead of the
  real runner; `ensure_config_key_value`, `ensure_config_line`, and
  `cmdline_ensure_token` divert their writes to a per-target scratch
  buffer. At the end, a unified diff against the current file prints
  per target. Tasks without a preview callback show as
  `(no preview available)`. Seven config-editing tasks ship preview
  callbacks: `boot_config`, `watchdog`, `pcie_gen3`, `pi5_fan`,
  `thermal_thresholds`, `oc_conservative`, `underclock`.
- **`--freeze-task <id>`** (repeatable) and YAML `freeze_tasks: [...]`.
  A frozen task is treated as already-completed by `apply_once` even
  under `--force`. Useful when a task regresses on a specific
  hardware generation and the user wants to pin an older version
  they've already applied.
- **Dockerised integration-test harness**
  ([tests/docker/Dockerfile](tests/docker/Dockerfile)). Debian Trixie
  base with stubs for `vcgencmd`, `rpi-eeprom-config`, `rpi-update`,
  and `rpi-eeprom-update` so the runtime reaches code paths that
  shellcheck alone cannot. A new `.github/workflows/integration.yml`
  builds the image and runs
  [tests/docker/run-tests.sh](tests/docker/run-tests.sh) on every
  push — covering `--help`, `--version`, `--list-tasks`,
  `--list-profiles --output json`, `--self-test`,
  `--validate-config` (good + bad paths), `--show-config`,
  `--completion bash/zsh`, `--diff` (no writes to `/boot/firmware`),
  `--freeze-task`, and the bundle build.

### Changed
- **`scripts/build-bundle.sh`** now refuses to produce a bundle when
  files exist in `lib/util/`, `lib/features/`, or `lib/ui/` that
  aren't listed in its build-order lists (prevents the silent-drop
  class of bug that caused 9.0.2's completion-feature hotfix).

### Notes
- The `--diff` helper deliberately seeds its scratch buffer from the
  real `/boot/firmware/*` files, so chained edits across multiple
  tasks compound correctly in the previewed output.
- `--watch` strips itself from the argv re-passed to the child, so
  `pi-optimiser --watch --yes --profile server` keeps `--yes
  --profile server` on every re-run without recursing into watch.

## 9.0.2 — 2026-04-19

Polish batch: reboot-required surfacing, YAML inline-comment
handling, stricter `--validate-config`, shell completion, installer
hygiene, and seven new introspection/maintenance flags. No
functional regressions; task registry unchanged.

### Added
- **Reboot-required surfacing**. Tasks that mutate
  `/boot/firmware/*` or EEPROM/firmware declare `reboot_required=1`
  in their `pi_task_register` call (11 tasks:
  `boot_config`, `libliftoff`, `oc_conservative`, `underclock`,
  `pi5_fan`, `pcie_gen3`, `thermal_thresholds`, `watchdog`,
  `eeprom_config`, `eeprom_refresh`, `firmware_update`). Docker's
  `--docker-cgroupv2` sub-option flags it inline. `apply_once`
  writes the flag into `CONFIG_OPTIMISER_STATE`; the post-run
  summary and `--report` (text + JSON) surface it prominently.
- **`--completion {bash,zsh}`** emits a completion script on
  stdout. The installer and updater drop the bash completion into
  `/etc/bash_completion.d/pi-optimiser`. Completes task IDs after
  `--only` / `--skip` / `--undo`, profile names after `--profile`,
  `text`/`json` after `--output`, paths after `--config` /
  `--restore` / `--validate-config`, shells after `--completion`.
- **`--show-config`** dumps the effective config (CLI + YAML +
  defaults) to stdout in a human-readable table. Useful for
  debugging profile / config precedence. Honours `--output json`.
- **`--undo --all`** rolls back every task that has a backup
  journal, newest-first. Skipped with a prompt unless `--yes`.
- **`--self-test`** runs every task's hardware + binary-availability
  preconditions read-only and prints a pass/skip table. No side
  effects; safe on production.
- **`--reboot-after <minutes>`** schedules `shutdown -r +<mins>`
  after a successful run, but only when a reboot-required task
  actually completed.
- **Man page**. `share/man/pi-optimiser.8.md` ships in the tree;
  installer/updater compiles it to `/usr/local/share/man/man8/
  pi-optimiser.8.gz` when `pandoc` is available (silently skipped
  otherwise). `man pi-optimiser` then just works.
- **JSON schema docs** under `docs/json-output.md` covering
  `--status`, `--report`, `--check-update`, `--list-profiles`, and
  `--show-config`.
- **YAML inline comments**. `key: value  # comment` now parses as
  `key: value`; double-quoted values keep any `#` they contain.
- **TUI `TERM=dumb` guard**. `pi_tui_available` now refuses to
  launch whiptail on a non-capable terminal, falling back to
  plain-stdout mode.

### Fixed
- `--validate-config` on a non-YAML file (e.g. `/etc/hosts`) no
  longer returns "Config OK". A recognised top-level key
  (`version`, `profile`, `integrations`, `hardware`, `firmware`,
  `security`, `system`) must be present.
- `install.sh` no longer prints a spurious `curl: (22) 404` when
  the ref is a tag (previously tried `refs/heads/` first and fell
  back to `refs/tags/`). Now tries tags first, errors silenced.
- `--restore` now rotates `/etc/pi-optimiser/backups/` aside to
  `backups.pre-restore-<ts>/` so a subsequent `--undo` doesn't
  undo the restore itself.
- The single-file release bundle now refuses `--migrate` and
  `--update` with a clear message (both require the multi-file
  install). `PI_OPTIMISER_BUNDLED` is no longer dead code.

### Security
- No new vectors discovered. The YAML shlex-quote fix from 9.0.1
  now also covers the inline-comment path (values are still
  quoted before eval).

---

## 9.0.1 — 2026-04-19

Second-pass audit hardening on top of the 9.0.0 refactor. Three
parallel code-review agents plus full live verification on a Pi 5
(Trixie, aarch64) surfaced 20+ items; the CRIT + HIGH + shipping-MED
bucket is addressed here.

### Security
- `lib/util/config_yaml.sh`: YAML values are now `shlex.quote()`-ed
  in Python before the bash `eval`, closing a root RCE where a
  malicious `config.yaml` could execute arbitrary shell.
- `lib/features/snapshot.sh`: `--restore` refuses tarballs with
  absolute paths, `..` traversal, or symlinks whose targets leave
  the archive. Extraction drops `--absolute-names` and uses
  `--no-same-owner` + `--no-overwrite-dir`.
- `lib/tasks/proxy.sh`: `$PROXY_BACKEND` is validated with
  `validate_proxy_backend_url` before it's written into the
  nginx `proxy_pass` directive. Prevents directive injection
  (previously a `;` or `{` in the URL could inject nginx config).
- `lib/tasks/ssh_import.sh`: `--ssh-import-github <handle>` is
  validated as an RFC-compliant GitHub handle.
- `lib/features/undo.sh`: `--undo <task-id>` is validated as
  snake_case so it cannot escape `/etc/pi-optimiser/backups/`.
- `/etc/pi-optimiser/{snapshots,backups}` and the eeprom staging
  dir are now `chmod 700` (were `755`).

### Correctness
- `flock -n 9` on `/var/lock/pi-optimiser.lock` serializes concurrent
  human / update-timer runs; state files are no longer race-corrupted.
- Config-load now runs **before** `parse_args` so CLI flags override
  on-disk values. An argv pre-scan catches `--no-config`, `--config`,
  and info-only flags (`--help`/`--version`/`--list-tasks`/
  `--list-profiles`/`--validate-config`) so the load is skipped
  where it would be noise.
- `--dry-run` now honoured by every feature: `--snapshot`, `--restore`,
  `--undo`, `--update`, `--migrate`, `--uninstall`, `--rollback`,
  `--enable-update-timer`, `--disable-update-timer`. Previously
  `--dry-run --update` actually pulled the tarball and swapped the
  launcher.
- `--force --dry-run` no longer mutates `state.json` — `--dry-run`
  stays strictly read-only even when `--force` is set.
- Five remaining tasks switched from raw `python3 <<'PY'` to the
  `run_python` wrapper: `ssh_import` (×2), `fstab`, `hostname`,
  `libliftoff`, `screen_blanking`. Exceptions now propagate through
  `log_warn` instead of being silently swallowed.
- `ssh_import`'s two ~27-line dedup blocks were refactored into a
  single `_ssh_import_merge_keys` helper.
- `var_log_tmpfs` now returns 1 when `systemctl start systemd-journald`
  fails after the remount (was silently reporting "completed").
- `--install-tailscale --install-wireguard` (without
  `--allow-both-vpn`) and `--overclock-conservative --underclock`
  now exit 1 at parse time with a clear message.
- `state.json` corruption (hand-edit with a trailing comma) is
  detected, the bad file is moved aside as `state.json.corrupt-<ts>`,
  and a clean schema-v2 file is written with a warning.
- `state.schema > PI_STATE_SCHEMA_TARGET` now aborts instead of
  silently mis-parsing newer fields as older.
- Main run loop captures task failures and exits 1 at the end
  (was tripping `set -e` mid-loop and skipping
  `print_run_summary`).

### UX / output
- `--check-update` returns exit code **10** when an update is
  available, **0** when up-to-date. CI can now gate:
  `if ! pi-optimiser --check-update; then pi-optimiser --update; fi`.
- New `--list-profiles` (text + `--output json`).
- New `--validate-config <path>` — parse-check a YAML config with
  no side effects.
- `--no-config` bypasses `/etc/pi-optimiser/config.yaml`.
- All `--*  --output json` streams (`--status`, `--report`,
  `--check-update`) keep stdout clean — log preamble routed to
  stderr when JSON is requested.
- `proxy` task's default-site restore preserves regular-file
  contents via a `.pi-optimiser.<ts>` backup (was leaving a broken
  self-symlink).
- `report.sh` JSON `schema_version` default aligned with
  `PI_STATE_SCHEMA_TARGET` (was 1, now 2).
- `pi_task_register` warns on duplicate registrations rather than
  silently overriding.

### Polish
- `share/logrotate/pi-optimiser` shipped; `install.sh`,
  `lib/features/install.sh`, and `lib/features/update.sh` drop it
  into `/etc/logrotate.d/`. Weekly rotation, keep 4, compressed.
- New `skip_var` task metadata: `screen_blanking` declares
  `skip_var=KEEP_SCREEN_BLANKING` so dry-run summaries distinguish
  "would run" / "not requested" / "suppressed by X".
- Dead code removed: `ensure_line_in_file`, `pi_supports_eeprom`.

### Infrastructure
- ShellCheck `--severity=warning` stays at rc=0 across every module.
- `.github/workflows/release.yml` attaches the single-file bundle
  plus `.sha256` on every `v*` tag push.

---

## 9.0.0 — 2026-04-19

Major refactor: a 2900-line monolith becomes a modular framework
with 15 utility modules, 42 task files, 6 framework features, a
whiptail TUI, and a self-update path. Migrated 32 existing tasks
1:1 (task IDs preserved) and added 10 new ones.

### Added
- `/opt/pi-optimiser` install layout; `curl | sudo bash install.sh`
  bootstrap; `--migrate` promotes a dev checkout.
- Per-task metadata fences + `pi_task_register` at source time;
  `lib/MANIFEST` drives execution order.
- Return-code contract: `0` = done, `1` = fatal, `2` = skipped with
  reason. `pi_skip_reason` + `return 2` replaces the global
  `TASK_WAS_SKIPPED`.
- State schema v2 (JSON) with automatic v1 → v2 migration;
  per-task version recorded on completion; `--status` shows
  `CURRENT` / `RAN` columns.
- Framework features: `--profile {kiosk,server,desktop,headless-iot}`,
  `--report` (text + JSON), `--snapshot` / `--restore`,
  `--undo <task>`, `--yes` / `--non-interactive`,
  `--update` / `--check-update` (opt-in), `--enable-update-timer`,
  `--require-signature` (minisign verifier, opt-in).
- whiptail TUI with category checklists, input forms, config-file
  round-trip via `/etc/pi-optimiser/config.yaml`.
- Single-file release bundle via `scripts/build-bundle.sh`; attached
  to GitHub releases via `.github/workflows/release.yml`.
- 10 new tasks: `pcie_gen3`, `thermal_thresholds`, `underclock`,
  `wifi_bt_power`, `dns_cache`, `wireguard`, `node_exporter`,
  `smartmontools`, `cli_bundle_modern`, `net_diag_bundle`.
- Docker task absorbs `--docker-buildx-multiarch`
  (qemu-user-static + binfmt seed) and `--docker-cgroupv2` as
  sub-flags.
- `AGENTS.md` for contributor guidance.

### Fixed (vs 7.5)
- fstab `noatime` regex was using `[^\s]` inside an ERE
  character-class, which matches "anything except `\` and `s`".
- Proxy task validated nginx **after** removing the default site.
  Now the original is backed up and restored on validation failure.
- `apt_update_once` aborted the whole run on a failed `apt-get update`.
- `/boot/firmware/*` was hardcoded; falls back to `/boot/*` on
  pre-Bookworm images.
- `unattended-upgrade` binary path resolved at run-time (was
  hardcoded to `/usr/bin`).
- `secure_ssh` installed `fail2ban` *after* reloading sshd; now
  before.
- Tailscale/Docker repo codename falls back to `bookworm` on 404.
- Backup files rotate (keep N most recent per target; default 5).
- `journald` stops / starts around `/var/log` remount (previously
  a race).
- `eeprom_config` temp files are removed via a RETURN trap even
  on early exit.
- `--install-zram --zram-algo disabled` now warns.

### Changed
- Entry path `/usr/local/sbin/pi-optimiser` (installed) /
  `./pi-optimiser.sh` (from a checkout) / single-file bundle
  (`pi-optimiser-v<tag>.sh` from releases).
- `SCRIPT_DIR` resolved via `readlink -f` so the launcher symlink
  points at the real release tree.
- `log_with_level` tolerates a non-writable log file (non-root
  invocations of `--version` no longer emit "Permission denied").

---

## 7.6.0 — 2026-04-19 (internal P1 drop; never tagged)

Extracted 14 utility modules and closed the remaining v7.5 bugs in
preparation for the 9.0 refactor. Shipped as the foundation of
9.0.0; no separate tag.

---

## 7.5 and earlier

See git history: commits `51d9068`, `789b5bc`, `4e335f9`,
`f470be0`, `88fdae7`, `8f45c90`, `86e69fd`.
