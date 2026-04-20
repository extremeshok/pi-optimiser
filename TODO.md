# TODO — deferred items

Tracked here so new contributors can pick them up without another
audit pass surfacing the same thing. Organised by effort.

## Medium (a session or two)

- **`--pin-task <id>=<version>`.** The `--freeze <id>` half of
  per-task version pinning ships (via `freeze_tasks:` in
  config.yaml, consulted by `apply_once`). The fetch-historical
  half is deferred: it needs a per-task version manifest fetched
  from a tag archive. Useful when a specific task regresses on a
  specific hardware generation but not a correctness need.

## Deliberately not planned

- **Self-update signing infrastructure.** The `--require-signature`
  verifier is shipped and will check a minisign signature if the
  user opts in and provides their own key. We are not going to
  produce an official signing pipeline:
  - For a single-maintainer project, the signing key and the
    GitHub credentials basically live in the same blast radius.
    If one is compromised, the other probably is too.
  - The `curl | sudo bash install.sh` path is unsigned anyway,
    and it's the more common install mode. Signing the release
    bundle protects one entrypoint while leaving the more common
    one exposed.
  - TLS + pinned-tag + sha256 matches the trust posture of every
    other `curl | bash` installer on the internet, and that is
    already what users sign up for when using this project.
  - Real-world supply-chain incidents (rustup-init, homebrew
    formulae, event-stream) were CI/build-system compromises
    that signing wouldn't have prevented.
  Users who need stricter verification can sign the bundle with
  their own key and run with `--require-signature`.

## Low (parked; narrow audience)

- **`headless_gpu_mem`** — `gpu_mem=16` for truly headless Pi 4 /
  Pi 3 installs. Pi 5 ignores it (unified memory). Not big enough
  to be worth its own task until someone asks.
- **`chrony`** — alternative to systemd-timesyncd for flaky-network
  devices (mobile Pis, 3G-backed IoT). `apt install chrony` +
  disable timesyncd. Edge case.
- **`ipv6_disable`** — sysctl `net.ipv6.conf.all.disable_ipv6=1`.
  Controversial and mostly cargo-culted; won't ship by default.
- **`usb_uas_quirks`** — `usb-storage.quirks=VID:PID:u` for UASP-
  broken SSD adapters. Case-specific per enclosure; hard to
  automate safely.

## Resolved (see CHANGELOG.md)

- **9.2.1**: state-driven UFW rules + auto-reconcile via
  fingerprint; Docker + Pi Connect in their own "Extra services"
  TUI menu; `remove_bloat` purges CUPS on non-desktop profiles.
- **9.2.0**: six new tasks — `power_off_halt` (Geerling's Pi 5
  vampire-power tip), `ufw_firewall`, `nvme_tune` (NVMe APST
  compat), `quiet_boot`, `disable_leds`, `pi_connect`. `sysctl`
  bumped to include TCP BBR + fq qdisc. Profile bundles refreshed.
- **9.1.2**: centralised `pi_validate_mutex()` so CLI / YAML / TUI
  paths catch conflicting task pairs (OC↔underclock, Tailscale↔
  WireGuard unless `allow_both_vpn`). New
  `integrations.allow_both_vpn` YAML key.
- **9.1.1**: TUI-selection gate-var fix (ticked items now flip
  their gate to 1 so tasks don't self-skip); boot_config no longer
  emits Pi-4-only keys on Pi 5; `usage()` shows `pi-optimiser`
  without `./` when launched via the installed symlink. TUI
  remembers prior selections and un-ticks persist (visited-
  categories reset).
- **9.1.0**: Prometheus textfile metrics, `--watch` mode,
  `--diff` preview for config.txt/cmdline.txt, `--freeze-task`,
  Dockerised integration-test harness, bundle parity guard.
- **9.0.2**: reboot-required surfacing, YAML inline comments,
  stricter `--validate-config`, `--completion`, `--show-config`,
  `--undo --all`, `--self-test`, `--reboot-after`, man page,
  JSON schema docs, `TERM=dumb` guard, bundle-mode guards on
  `--migrate` and `--update`, stale-journal rotation on
  `--restore`, `install.sh` cleaner 404 path.
- **9.0.1**: 3 CRITs + 10 HIGHs + 10 MEDs from audit pass #2.
  See `CHANGELOG.md` for the full list.
- **9.0.0**: modular refactor, self-update, TUI, installer.
