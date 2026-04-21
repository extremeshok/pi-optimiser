---
title: PI-OPTIMISER
section: 8
header: System Manager's Manual
footer: pi-optimiser 9.4.3
date: 2026-04
---

# NAME

pi-optimiser — Raspberry Pi OS hardening and tuning framework

# SYNOPSIS

**pi-optimiser**

**pi-optimiser** \[*flags*\]

**pi-optimiser --only** *task* \[**--only** *task* ...\] \[**--yes**\]

**pi-optimiser --profile** {kiosk|server|desktop|headless-iot} \[**--yes**\]

**pi-optimiser --report** \[**--output** *fmt*\]

**pi-optimiser --update** \[**--require-signature**\] \[**--yes**\]

# DESCRIPTION

pi-optimiser is a modular hardening and tuning framework for
Raspberry Pi OS. It ships 40+ tasks across storage, networking,
security, packages, firmware, and hardware tuning. Every task records
completion state under `/etc/pi-optimiser/state.json`.

The framework includes a whiptail TUI (launched on an interactive
TTY with no action flags), opt-in self-update from GitHub,
configuration via `/etc/pi-optimiser/config.yaml`, pre-change
snapshots, per-task undo via backup journals, and JSON output for
scripting.

For most operators the intended entry point is simply:

```text
sudo pi-optimiser
```

That opens the guided menu, suggests a starting profile, lets the
operator toggle task categories, fill in values such as hostname or
timezone, and then apply the selected changes. CLI flags remain the
advanced path for automation, remote rollouts, and repeatable batch
runs.

# INTERACTIVE MODE

When pi-optimiser is launched on an interactive TTY with no action
flags, it opens the whiptail interface by default.

The TUI flow is:

1. Welcome screen with a suggested profile.
2. Main menu with category-driven task selection.
3. Value forms for hostname, timezone, locale, proxy, and SSH keys.
4. Apply step that saves `/etc/pi-optimiser/config.yaml` and runs the
   chosen tasks.

Use **--tui** to force the menu and **--no-tui** to suppress it.

# COMMON FLAGS

**--only** *task*
: Run only the named task. Repeatable.

**--skip** *task*
: Skip the named task. Repeatable.

**--dry-run**
: Print what would happen, no side effects. Classifies each task
as `(dry-run)` / `(not requested)` / `(suppressed by VAR)`.

**--force**
: Re-run tasks marked completed. Read-only under `--dry-run`.

**--yes**, **-y**, **--non-interactive**
: Skip confirmation prompts.

**--profile** *name*
: Apply the named flag bundle: *kiosk*, *server*, *desktop*,
*headless-iot*.

**--config** *path*
: Load a YAML config. CLI flags still override individual keys.

**--no-config**
: Ignore `/etc/pi-optimiser/config.yaml` even if present.

**--output** *fmt*
: Emit machine-readable output: *text* (default) or *json*.
Applies to **--status**, **--report**, **--check-update**,
**--list-profiles**.

# INFO COMMANDS

**--version**, **--help**
: Self-explanatory.

**--list-tasks**
: Show every registered task with version and category.

**--list-profiles**
: Show every profile and what it enables (text + JSON).

**--status**
: Task-by-task completion table with version drift.

**--report**
: Full system state overview — hardware, throttle, temperatures,
disk, disabled services, task summary, reboot-required flag.

**--show-config**
: Dump the effective config after CLI + YAML + defaults merge.

**--validate-config** *path*
: Parse-check a YAML config without side effects.

**--completion** *shell*
: Emit a completion script for *bash* or *zsh* on stdout.

**--self-test**
: Run every task's hardware and binary-availability precondition
read-only; report pass/skip per task.

# MAINTENANCE

**--snapshot**
: Tar `/etc/fstab`, boot config, sysctl, limits, sshd, apt,
`/etc/pi-optimiser`, into `/etc/pi-optimiser/snapshots/<ts>.tgz`.

**--restore** *archive*
: Reverse a snapshot. Refuses archives with absolute paths, `..`
traversal, or escaping symlinks.

**--undo** *task*
: Restore the files *task* last modified from the journal at
`/etc/pi-optimiser/backups/<task>.json` and clear the state marker.

**--undo --all**
: Roll back every task with a journal, most recent first.

**--reboot**
: If any reboot-required task succeeds, issue `shutdown -r now`
immediately after the run completes. Safe for remote Pis — always
restarts rather than halts.

**--diff**
: Preview mode. Invokes each config-editing task's preview
callback, diverts `config.txt` and `cmdline.txt` writes to a
scratch buffer, and prints a unified diff of every proposed
change against the current file. No side effects.

**--freeze-task** *id*
: Treat *id* as already-completed even under `--force`.
Repeatable. Also settable via `freeze_tasks: [...]` in
`config.yaml`.

**--watch**
: After the initial run, block on `inotifywait` against
`config.yaml` and re-exec on change. Requires `inotify-tools`;
falls back to a 10-second polling loop when absent. Survives
task failures; only SIGINT ends the watcher.

**--no-metrics**, **--metrics-path** *path*
: Skip or relocate the Prometheus textfile-collector output
(default `/var/lib/node_exporter/textfile_collector/pi-optimiser.prom`
when that directory exists, else `/etc/pi-optimiser/metrics/pi-optimiser.prom`).

**--install-firewall**
: Install UFW, set deny-in / allow-out, and open the detected SSH
port, ICMP, and any active `tailscale0` or `wg*` interface.

**--power-off-halt**
: Pi 5 only. Set EEPROM `POWER_OFF_ON_HALT=1` so the 3V3 rail cuts
on shutdown (~0.01 W idle vs ~1.2 W). Incompatible with HATs that
need 3V3 while the Pi is "off".

**--nvme-tune**
: Add `nvme_core.default_ps_max_latency_us=0` to cmdline.txt so
APST is disabled — works around several Pi 5 NVMe HAT + SSD
combinations that drop out under APST.

**--quiet-boot**
: Hide the rainbow splash (`disable_splash=1`) and silence kernel
log output at boot (`quiet loglevel=3`).

**--disable-leds**
: Turn off the activity, power, and both ethernet LEDs for
headless / rack-mounted installs.

**--install-pi-connect**
: Install the official Raspberry Pi Connect package
(`rpi-connect`, or `rpi-connect-lite` when no display is attached).
The operator still runs `rpi-connect signin` to pair the device.

**--remove-cups**
: Force-purge CUPS + printer-driver packages and their
`avahi-daemon` / `colord` dependencies. Done automatically for
`kiosk`, `server`, and `headless-iot` profiles (and whenever
`KEEP_SCREEN_BLANKING=1`); use this flag to force the purge on a
plain-desktop install that doesn't need printing.

**--headless-gpu-mem**
: Pi 4 / Pi 400 / Pi 3 / Pi Zero 2 only. Set `gpu_mem=16` to hand
~50-240 MB back to the ARM side on a headless install. Pi 5 and
Pi 500 skip automatically (unified memory architecture; `gpu_mem`
is ignored by the firmware). Applied by `server` and
`headless-iot` profiles.

**--install-chrony**
: Install `chrony` as the active time sync daemon, replacing
`systemd-timesyncd` (which the package masks at install time).
Handles large clock steps and intermittent connectivity better —
the typical win is on mobile / 3G-backed / solar-powered IoT Pis.

**--disable-ipv6**
: Disable IPv6 via `/etc/sysctl.d/98-pi-optimiser-ipv6.conf`. The
drop-in lists the three keys it sets so `--undo` or a manual
`rm` restores IPv6 cleanly.

**--usb-uas-quirks**
: Probe `lsusb` against a built-in list of USB-SATA/NVMe bridges
known to misbehave under UAS (JMS578, JMS567, JMS583, ASM1153E,
VL715, RTL9210) and append `usb-storage.quirks=VID:PID:u,...` to
`cmdline.txt`. Reboot required.

**--usb-uas-extra** *VID:PID[,VID:PID…]*
: Extend the UAS-quirk list with additional pairs the operator
discovered via `dmesg | grep -i uas`. Implies `--usb-uas-quirks`.

**--install-hailo**
: Pi 5 / Pi 500 only. Install the Hailo NPU driver stack for the
Raspberry Pi AI Kit and AI HAT+ (`hailo-all` metapackage, falling
back to the split `hailort` + `hailo-dkms` + `python3-hailort` +
`hailo-tappas-core` + `hailofw` list on older Bookworm images).
Probes `lspci` for the Hailo device and warns on kernels older
than 6.6.31 (where `hailo-dkms` fails to build). Reboots required
for the DKMS module to attach. Pair with `--pcie-gen3` for full
AI HAT+ throughput.

# SELF-UPDATE (opt-in)

**--check-update**
: Exit 10 if a newer commit exists on the configured ref, 0 if
synced, non-zero on other errors.

**--update**
: Pull the configured ref from GitHub
(env: `PI_OPTIMISER_REF`, default *master*), verify with
`bash -n` on the staged tree, atomic-swap
`/opt/pi-optimiser/current`, record commit SHA in state.

**--require-signature**
: Refuse `--update` unless a minisign signature is present
alongside the tarball. Verifier ships; the operator supplies
their own public key (no official signing pipeline — see the
README Security section for the rationale).

**--enable-update-timer**, **--disable-update-timer**
: Install/remove a daily systemd timer running `--update --yes`
with a 6h `RandomizedDelaySec`.

# INSTALL LAYOUT

**--migrate**
: Promote the calling checkout into `/opt/pi-optimiser/releases/`
and symlink `/usr/local/sbin/pi-optimiser`.

**--uninstall**
: Remove `/opt/pi-optimiser/` and the launcher symlink. State
at `/etc/pi-optimiser/` is preserved.

**--rollback**
: Flip `/opt/pi-optimiser/current` to the previous release.

# FILES

`/etc/pi-optimiser/state.json`
: Schema-v2 JSON task-completion record. Written by `set_task_state`.

`/etc/pi-optimiser/state.schema`
: Single integer; current schema version.

`/etc/pi-optimiser/config.yaml`
: User-editable config. Loaded before `parse_args` so CLI wins.

`/etc/pi-optimiser/backups/<task>.json`
: Per-task backup journal. Consumed by `--undo`.

`/etc/pi-optimiser/snapshots/<ts>.tgz`
: Snapshots, `chmod 0700` on the directory.

`/var/log/pi-optimiser.log`
: Run log. Rotated weekly by `/etc/logrotate.d/pi-optimiser`.

`/var/lock/pi-optimiser.lock`
: `flock`-held lock serializing concurrent runs.

`/opt/pi-optimiser/current -> releases/<id>/`
: Active release tree; flipped atomically by `--update`.

`/usr/local/sbin/pi-optimiser`
: Launcher symlink resolved via `readlink -f`.

`/etc/bash_completion.d/pi-optimiser`
: Bash completion, regenerated on install/update.

`/var/lib/node_exporter/textfile_collector/pi-optimiser.prom`
: Prometheus metrics (if the directory exists). Fallback path is
`/etc/pi-optimiser/metrics/pi-optimiser.prom`. Override via
`--metrics-path`.

# EXIT CODES

- **0** — success or read-only info command returned cleanly.
- **1** — one or more tasks failed, or a feature returned an error.
- **10** — `--check-update`: an update is available.

# SEE ALSO

**systemctl**(1), **flock**(1), **whiptail**(1), **minisign**(1),
**rpi-eeprom-config**(8), **rpi-update**(8)

Full documentation at
<https://github.com/extremeshok/pi-optimiser>.
