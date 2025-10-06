# pi-optimiser

A one-shot hardening and tuning script for **Raspberry Pi OS (Bookworm/Trixie or newer, 64-bit)**. It trims fat, reduces SD wear, enables kiosk-friendly defaults, and records every change so repeated runs stay safe.

## What You Get
- **Hardware-aware configuration** for Pi 5/500, Pi 4/400, Pi 3, and Pi Zero 2, with preflight checks for throttling, power issues, and connectivity before any changes.
- **Storage longevity** tweaks: aggressive apt hygiene, tmpfs mounts for `/tmp` and `/var/log`, journal rate limits, and pessimistic writeback tuning.
- **Optional extras** you can add à la carte: Tailscale, Docker, conservative overclocking per model, NGINX proxy, kiosk display tuning, and SSH hardening with fail2ban.
- **Auditability**: every task logs to `/var/log/pi-optimiser.log`, state lives in `/etc/pi-optimiser/state`, and backups carry timestamped `.pi-optimiser.*` suffixes.

## Quick Start
```bash
chmod +x pi-optimiser.sh
sudo ./pi-optimiser.sh
```
Reboot afterwards so mounts, sysctl values, and firmware tweaks are applied.

Helpful commands:
- `sudo ./pi-optimiser.sh --status` – show task history and timestamps.
- `sudo ./pi-optimiser.sh --list-tasks` – see available tasks.
- `sudo ./pi-optimiser.sh --dry-run` – preview work without touching the system.

## Command-line Flags
| Flag | Description |
|------|-------------|
| `--force` | Re-run tasks even if marked complete. |
| `--dry-run` | Log intended actions only. |
| `--status` | Print task status table and exit. |
| `--list-tasks` | Show task list with descriptions. |
| `--skip <task>` | Skip a task (repeatable). |
| `--only <task>` | Run only specific tasks (repeatable). |
| `--install-tailscale` | Enable the Tailscale task. |
| `--install-docker` | Enable the Docker task. |
| `--locale <locale>` | Configure system locale, e.g. `en_GB.UTF-8`. |
| `--proxy-backend <url|off|disable|disabled>` | Manage the NGINX proxy helper. |
| `--zram-algo <lz4|zstd>` | Override the default ZRAM compression (defaults to `lz4`). |
| `--overclock-conservative` | Apply firmware-safe CPU/GPU clocks on Pi 5/500, 4/400, 3, and Pi Zero 2 (power-health required). |
| `--secure-ssh` | Disable root SSH login, keep user passwords, and enable fail2ban. |
| `--keep-screen-blanking` | Preserve default screen blanking. |
| `--help` / `--version` | Self-explanatory. |

Combine flags as needed, for example:
```bash
sudo ./pi-optimiser.sh --install-tailscale --proxy-backend http://127.0.0.1:8080 --secure-ssh
```

## Tasks & Behaviour
The script executes these tasks in order unless skipped. **Optional** tasks require their respective flags.

| Task ID | Purpose |
|---------|---------|
| `remove_bloat` | Purge bundled educational/demo packages and clean apt caches. |
| `fstab` | Add `noatime` + longer commit interval to `/`. |
| `tmpfs_tmp` | Mount `/tmp` on tmpfs (200 MB). |
| `var_log_tmpfs` | Move `/var/log` to tmpfs (50 MB) and recreate structure via tmpfiles. |
| `disable_swap` | Disable `dphys-swapfile` and turn off swap. |
| `zram` | Size compressed swap to RAM tier (defaults to `lz4`, override with `--zram-algo`). |
| `journald` | Keep the journal in RAM with 50 MB runtime limit. |
| `sysctl` | Apply writeback, swappiness, inotify, and net backlog tweaks. |
| `apt_conf` | Harden unattended apt jobs and trim caches. |
| `unattended` | Configure security-only unattended upgrades on a 6‑hour timer. |
| `cli_tools` | Install useful CLI utilities (`htop`, `tmux`, `pigz`, etc.). |
| `locale` | Set `/etc/default/locale` when `--locale` is provided. |
| `limits` | Raise user/system file descriptor and process limits. |
| `screen_blanking` | Disable console + LightDM blanking (unless `--keep-screen-blanking`). |
| `disable_services` | Turn off non-essential services (Bluetooth, avahi-daemon, cups, etc.). |
| `proxy` † | Manage the NGINX reverse proxy (`--proxy-backend URL` or disable). |
| `boot_config` † | Apply display-friendly defaults for Pi 4/400 and Pi 5/500 firmware. |
| `libliftoff` † | Ensure vc4 KMS overlays disable liftoff to curb compositor glitches. |
| `oc_conservative` † | Conservative overclock per model (Pi 5/500, 4/400, 3, Zero 2). |
| `secure_ssh` † | Harden sshd (no root login) and enable fail2ban sshd jail. |
| `tailscale` † | Install/enable Tailscale repository and service. |
| `docker` † | Install Docker Engine (preferred repo or distro fallback). |

† Runs only when the associated flag is supplied.

### Conservative Overclock Profiles
| Model | Profile Applied | Notes |
|-------|-----------------|-------|
| Pi 5 / Pi 500 | `arm_freq=2400`, `gpu_freq=900` | Requires healthy power (checked in preflight). |
| Pi 4 | `arm_freq=1750`, `gpu_freq=600` | |
| Pi 400 | `arm_freq=2000`, `gpu_freq=600` | Matches official 2 GHz support. |
| Pi 3 | `arm_freq=1400`, `gpu_freq=500` | |
| Pi Zero 2 | `arm_freq=1200`, `gpu_freq=500` | |

If preflight detects undervoltage or throttling, the overclock task is skipped automatically.

### SSH Hardening (`--secure-ssh`)
- Forces `PermitRootLogin no` while keeping `PasswordAuthentication yes` for regular users.
- Disables challenge-response auth and ensures PAM stays enabled.
- Installs fail2ban with a systemd-backed `sshd` jail (5 retries, 10‑minute ban).
- Reloads the `ssh` service and enables `fail2ban.service`.

## Hardware & Safety Checks
Before tasks run, the script:
1. Captures model, firmware, RAM size, boot device, and kernel.
2. Parses `vcgencmd get_throttled` and temperature readings, logging warnings or blockers.
3. Ensures the root filesystem has ≥512 MB free.
4. Tests network reachability (Google DNS and Cloudflare) to warn about package installs.

Power/thermal blockers skip safety-sensitive tasks (e.g., display tweaks and overclocking).

## Compatibility Notes
- Designed for Raspberry Pi OS with systemd (Bookworm/Trixie+). Works on desktop or Lite images.
- Optimised and tested on Pi 5/500, Pi 4/400, Pi 3, Pi Zero 2. Earlier models run most tasks but overclocking is skipped.
- Requires Bash 4+ (Pi OS ships with Bash 5). Run as `root` or via `sudo`.

## Logging & Rollback
- State: `/etc/pi-optimiser/state` (CSV-like: task, status, timestamp, description).
- Backups: original files gain `.pi-optimiser.YYYYMMDDHHMMSS` suffix.
- Config log: `/var/log/pi-optimiser.log` records every action.

To undo specific changes, restore from the backup file you need or re-run with `--only <task>` after manually reverting.

## Troubleshooting
- **Dry run first** on systems you care about: `sudo ./pi-optimiser.sh --dry-run`.
- **SSH access**: after enabling `--secure-ssh`, ensure key-based auth is in place. Root login via SSH is blocked.
- **Tailscale**: run `sudo tailscale up` manually after installation to join your network.
- **Docker**: a reboot is recommended to load the cgroup hierarchy cleanly if installing Docker.

## Contributing
Issues, feature ideas, and PRs are welcome. Please include:
- `./pi-optimiser.sh --status` output
- Relevant `/var/log/pi-optimiser.log` excerpts
- Raspberry Pi model and Raspberry Pi OS release info (`/etc/os-release`)

