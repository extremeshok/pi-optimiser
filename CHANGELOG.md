# Changelog

## 9.4.4 — 2026-04-21

### Fixed
- **`hostname` / `timezone` / `locale` re-run when the requested value
  changes.** Previously, once the task was marked `completed` in
  `state.json`, changing `--hostname`, `--timezone`, or `--locale`
  (or the equivalent config-file values) on a later invocation was a
  no-op — the user had to add `--force` to get the new value applied.
  `apply_once` now consults an optional per-task hook
  `pi_<id>_value_changed`. When it returns 0 (the live system
  `hostname` / timezone / `/etc/default/locale` LANG differs from the
  requested value), the completed short-circuit is bypassed and the
  task re-runs, logging "Re-running <task>: requested value differs
  from current system state". Task versions bumped: `hostname` →
  1.2.0, `timezone` → 1.3.0, `locale` → 1.3.0.

## 9.4.3 — 2026-04-21

### Docs
- **README expanded** with CI/release/licence badges, a "Why People Use
  It" section, common use cases (headless server, daily desktop, kiosk,
  headless-iot), a "Quick Start / Watch Demo / Menu Workflow / Advanced
  CLI" nav line, an Apply-writes-`config.yaml` hint, and a FAQ covering
  reboot behaviour, hand-written configs, rollback, and Desktop/Lite
  compatibility.
- **`docs/marketing-copy.md`** added with tagline, About box, short/full
  about, homepage hero, and listing copy for the repo "About" field,
  release posts, and future homepage use.

### Tests
- **TUI Apply round-trip** — new Docker-harness test confirms
  `_pi_tui_apply` auto-writes `/etc/pi-optimiser/config.yaml`, keeps
  only the ticked task gates in `ONLY_TASKS`, and that reloading the
  saved file restores hostname/timezone/locale/proxy and the selected
  `INSTALL_*` gates exactly.
- **Snapshot restore with relative symlinks** — verifies
  `pi_restore_snapshot` accepts safe relative symlinks (e.g.
  `/etc/default/locale → ../locale.conf`), extracts them intact, and
  moves the live `backups/` aside into `backups.pre-restore-*`.
- **`--reboot` scope** — asserts the flag is scoped to the current run:
  a stale `reboot_required` marker from a prior invocation does not
  trigger `shutdown -r now`, while a reboot-required task applied in
  this run (e.g. `quiet_boot` via boot-config change) does.
- **Flag coverage** — `--reboot` and `--show-config` added to the
  documented-flag acceptance sweep so every flag in the man page is
  exercised by `parse_args`.

## 9.4.2 — 2026-04-21

### Fixed
- **`disable_services` (→ 1.2.0) masks `openipmi.service`** — when
  `prometheus-node-exporter-collectors` is installed it pulls in
  `ipmitool` → `openipmi`. The service fails on every boot with
  "Starting ipmi drivers ipmi failed!" because a Pi has no IPMI BMC
  hardware. Masking it (not just disabling) prevents the unit from
  being started as a dependency.

## 9.4.1 — 2026-04-21

### Fixed
- **`full_upgrade` moved to `packages` TUI category** — was erroneously
  filed under `system`; it now appears in the Packages menu where it
  belongs alongside other apt-driven tasks.
- **TUI hardware menu resolves overclock/underclock conflict immediately**
  — previously both could be checked simultaneously and the error was
  only surfaced at Apply time. Now, if both `oc_conservative` and
  `underclock` are ticked when leaving the Hardware menu, a radiolist
  prompts the operator to pick one before returning to the main menu.

## 9.4.0 — 2026-04-21

### Added
- **`full_upgrade`** (system) — runs `apt-get update && full-upgrade
  && autoremove && autoclean`, all non-interactive
  (`DEBIAN_FRONTEND=noninteractive`, `--force-confdef/--force-confold`).
  Slots **first** in the manifest so every invocation starts with
  current packages. Unlike every other task it carries `always_run=1`
  and bypasses the `is_task_done` short-circuit — it deliberately
  reruns on every pi-optimiser call. Sets `APT_UPDATED=1` so
  subsequent `ensure_packages` calls skip the redundant
  `apt-get update`. Default-on; skip with `--skip full_upgrade`.
- **`--reboot`** flag — after a successful run, if any
  `reboot_required` task applied, issue `shutdown -r now` immediately.
  Always uses restart (`-r`), never halt, so remote Pis come back
  without manual power-cycling.
- **`always_run` task attribute** in `pi_task_register` — tasks that
  set `always_run=1` bypass the `is_task_done` completion-state check
  on every invocation. Useful for tasks that must be idempotent across
  runs by nature (upgrades, health checks) rather than by state record.

### Removed
- **`--reboot-after <mins>`** — replaced by `--reboot`. The delayed
  scheduler added complexity with no real benefit over scheduling
  a reboot externally; remote-Pi safety requires restart-not-halt
  semantics that `--reboot` enforces explicitly.

## 9.3.0 — 2026-04-20

Clears the Tier-3 research items and adds Hailo NPU support.

### Added (five new tasks)
- **`headless_gpu_mem`** (display) — Pi 4 / Pi 400 / Pi 3 / Pi Zero 2
  only. Sets `gpu_mem=16` to hand ~50-240 MB back to the CPU on
  headless deployments. Pi 5 / Pi 500 skip automatically because
  they use unified memory (VideoCore 7 + IOMMU) where `gpu_mem` is
  ignored. `boot_config` no longer sets `gpu_mem=320` when
  `KEEP_SCREEN_BLANKING=1` or `HEADLESS_GPU_MEM=1`, so the two no
  longer fight over that key.
- **`chrony`** (system) — swaps `systemd-timesyncd` for `chrony`,
  which handles large step-corrections and flaky connectivity
  better. Mobile / 3G-backed / solar-powered IoT Pis benefit most.
- **`ipv6_disable`** (network) — writes a dedicated sysctl drop-in
  at `/etc/sysctl.d/98-pi-optimiser-ipv6.conf` listing the three
  keys it sets. Opt-in (IPv6 is usually safer left on).
- **`usb_uas_quirks`** (storage) — probes `lsusb` against a
  built-in list of USB-SATA/NVMe bridges (JMS578, JMS567, JMS583,
  ASM1153E, VL715, RTL9210) known to misbehave under UAS and
  appends `usb-storage.quirks=VID:PID:u` to `cmdline.txt`. Extra
  pairs can be supplied via `--usb-uas-extra` /
  `hardware.usb_uas_extra`.
- **`hailo`** (integrations) — installs the Raspberry Pi AI Kit /
  AI HAT+ driver stack (`hailo-all` metapackage, with a fallback
  to the split packages for older images). Probes `lspci` for the
  NPU, warns on kernels older than 6.6.31, and suggests pairing
  with `--pcie-gen3` for full throughput. LLM / model inference
  deliberately out of scope — this task installs the driver layer
  only.

### Changed
- **Profile bundles refreshed** to use `HEADLESS_GPU_MEM` on
  `server` and `headless-iot` (no-op on Pi 5).
- **`boot_config`** conditionally skips `gpu_mem=320` when
  headless, so it and `headless_gpu_mem` can coexist without a
  last-write-wins race.

### Pi 500 support
Pi 500 has always been covered — `is_pi5()` matches both
"Raspberry Pi 5" and "Raspberry Pi 500" model strings, so every
Pi-5-gated task (`pcie_gen3`, `pi5_fan`, `oc_conservative`'s 2.8
GHz profile, `eeprom_config`, `power_off_halt`, `hailo`) applies
to the 500 transparently. This release confirms the behaviour in
the docs; no code changes were needed.

## 9.2.1 — 2026-04-20

### Changed
- **`ufw_firewall` (→ 1.1.0) opens ports only for services that are
  actually present, and auto-reconciles when that changes.**
  Previously it blindly allowed Tailscale / WireGuard interfaces
  whether they existed or not. Now:
  - Tailscale rule added only when `tailscale0` is up.
  - WireGuard rule added only for `wg*` interfaces that exist.
  - Proxy rule (80/tcp) added only when `PROXY_BACKEND` is set to a
    real URL or the `pi-optimiser-proxy` nginx symlink is in place.
  A fingerprint of these inputs is stored in
  `CONFIG_OPTIMISER_STATE.firewall.fingerprint` at end-of-run; the
  main loop compares the current fingerprint against stored on the
  next run and clears the task's completion marker when they differ
  — so adding Tailscale later triggers a re-reconciliation
  automatically, no `--force` needed.
- **Docker + Pi Connect moved to their own TUI menu** ("Extra
  services"). The category name (`integrations`) is unchanged so
  existing state markers stay valid; only the TUI top-level entry
  shifts. Firmware menu now cleanly shows just EEPROM/firmware
  tasks.
- **`remove_bloat` (→ 1.2.0) purges CUPS on non-desktop installs.**
  CUPS + printer-driver packages eat ~100 MB on Pi OS images and
  pull colord / avahi. Removed automatically for `kiosk`, `server`,
  `headless-iot` profiles, or when `KEEP_SCREEN_BLANKING=1` /
  `--remove-cups` / `system.remove_cups: true` is set. Desktop
  installs keep CUPS intact so printing keeps working.

## 9.2.0 — 2026-04-20

Research pass on Jeff Geerling's published work, official Raspberry
Pi forums, and the usual headless-hardening guides surfaced a handful
of gap-closers. All opt-in, all benign when skipped.

### Added (six new tasks)
- **`power_off_halt`** (firmware-eeprom) — Pi 5 EEPROM setting
  `POWER_OFF_ON_HALT=1` cuts the 3V3 rail on shutdown, dropping idle
  draw from ~1.2 W to ~0.01 W. Opt-in via `--power-off-halt` (some
  HATs need 3V3 while the Pi is "off"). Credit: Jeff Geerling.
- **`ufw_firewall`** (security) — installs UFW, sets deny-in /
  allow-out, and punches a hole for the detected SSH port, ICMP, and
  any `tailscale0` / `wg*` interface that exists. `--install-firewall`.
- **`nvme_tune`** (storage) — adds
  `nvme_core.default_ps_max_latency_us=0` to cmdline.txt so
  compatibility-bugged NVMe HAT + SSD combos stop hitting APST
  dropouts. `--nvme-tune`, reboot-required.
- **`quiet_boot`** (display) — `disable_splash=1` in config.txt plus
  `quiet loglevel=3` in cmdline.txt. Kills the rainbow splash and
  shrinks kernel log spam. `--quiet-boot`, reboot-required.
- **`disable_leds`** (display) — `act_led_trigger=none`,
  `pwr_led_trigger=none`, `eth_led0=4`, `eth_led1=4`. Saves ~15 mA
  and stops the strobe in rack-mounted Pis. `--disable-leds`,
  reboot-required.
- **`pi_connect`** (integrations) — installs Raspberry Pi Connect
  (WebRTC remote access, official), picking `rpi-connect` when a
  display is attached and the lighter `rpi-connect-lite` otherwise.
  Pairing (`rpi-connect signin`) remains an interactive user step.
  `--install-pi-connect`.

### Changed
- **`sysctl` task bumped to 1.2.0** — adds TCP BBR + fq qdisc
  (`net.core.default_qdisc=fq`,
  `net.ipv4.tcp_congestion_control=bbr`). Google's production default
  since ~2017; measurable throughput win on lossy / high-RTT links.
  Task verifies BBR actually loaded and warns on kernels too old to
  support it.
- **Profile bundles refreshed**:
  - `kiosk` adds `QUIET_BOOT=1` (no rainbow splash on signage).
  - `server` adds `INSTALL_FIREWALL=1` + `DISABLE_LEDS=1` (stops
    strobing in the rack, closes incoming-by-default).
  - `headless-iot` adds `DISABLE_LEDS=1` + `QUIET_BOOT=1` (quiet
    serial console, no wasted power on LEDs).
- **YAML config** gains six new keys:
  `integrations.pi_connect`, `hardware.quiet_boot`,
  `hardware.disable_leds`, `hardware.nvme_tune`,
  `firmware.power_off_halt`, `security.firewall`. Existing keys
  unchanged.
- **Help, completion (bash + zsh), and man page** updated for the
  six new flags.

## 9.1.2 — 2026-04-19

### Changed
- **Mutex validation is centralised.** Extracted into
  `pi_validate_mutex` (pi-optimiser.sh) so the CLI path, the
  config.yaml load path, and the TUI apply step all enforce the
  same rules. Current mutex pairs:
  - `overclock_conservative` vs `underclock` — hard conflict
    (opposing arm_freq / gpu_freq).
  - `tailscale` vs `wireguard` — hard conflict unless
    `allow_both_vpn` is true (CLI `--allow-both-vpn` or YAML
    `integrations.allow_both_vpn: true`).
  - `install_zram` + `zram_algo: disabled` — soft conflict; the
    "disabled" branch wins and a warning is printed.
  Previously the TUI could tick both halves of a mutex and the
  task loop would run one and awkwardly skip the other with a
  "conflicts with …" reason. The TUI apply step now catches the
  conflict up front and shows a dialog pointing at the fix.
- **`allow_both_vpn` is now a first-class YAML key** under
  `integrations:`, so operators can pin the decision in
  `/etc/pi-optimiser/config.yaml` instead of having to pass
  `--allow-both-vpn` on every run.

## 9.1.1 — 2026-04-19

Bug-fix pass on 9.1.0 addressing TUI behaviour, Pi 5 display
defaults, and usage text.

### Fixed
- **TUI selections now actually run.** Previously ticking a task in
  the TUI added it to `ONLY_TASKS` but didn't flip the task's
  `gate_var`; every task would then self-skip with
  `(not requested)`. `_pi_tui_apply` now sets the gate_var to `1`
  for every selected task (string-valued gates — hostname,
  timezone, locale, proxy, ssh_import — are still set via the
  Values forms menu).
- **boot_config task no longer sets Pi-4-only keys on Pi 5.**
  `gpu_mem`, `arm_boost`, `framebuffer_depth`, and
  `framebuffer_ignore_alpha` are legacy/firmware-framebuffer knobs
  that the Pi 5 firmware ignores (unified memory, always-rated
  clock, KMS-only). The shared entry list is now assembled by
  `_boot_config_entries` so `run_boot_config` and
  `pi_preview_boot_config` stay in sync. Pi 4 / Pi 3 / Zero 2
  behaviour is unchanged.
- **Usage line displays the right invocation form.** After
  `install.sh` the launcher sits at `/usr/local/sbin/pi-optimiser`;
  `--help` now prints `Usage: sudo pi-optimiser [options]` instead
  of the misleading `./pi-optimiser`. Running from a checkout still
  shows `./pi-optimiser.sh`.

### Docker CI
- Docker integration harness was aborting on a stale
  `grep -q 'profile:'` assertion (text-mode `--show-config` uses
  `PI_PROFILE`, not `profile:`). The test now checks for stable
  section headers in text mode and asserts the new top-level keys
  (`metrics`, `freeze_tasks`, `integrations`) in JSON mode.
- `actions/checkout` bumped to `@v5` across all workflows to
  silence the Node 20 deprecation warning.

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
