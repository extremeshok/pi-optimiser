# pi-optimiser JSON output schemas

Every command that accepts `--output json` emits a single JSON object
on stdout. Log lines go to **stderr** so the stdout stream is pure
JSON for `jq` / `python -m json.tool` / other consumers.

All schemas are stable within a schema major version. The
`schema_version` integer (where present) matches
`PI_STATE_SCHEMA_TARGET` in `lib/util/state.sh`; currently **2**.
Consumers should validate `schema_version` and fail loudly on any
future increment — every bump means at least one field was removed
or changed shape.

## `pi-optimiser --status --output json`

Task-by-task completion record, in manifest order.

```json
{
  "schema_version": 2,
  "order": ["remove_bloat", "fstab", "tmpfs_tmp", "…"],
  "tasks": [
    {
      "id": "cpu_governor",
      "status": "completed",
      "timestamp": "2026-04-19T10:54:14+02:00",
      "task_version_ran": "1.1.0",
      "description": "Keep the CPU at full speed (performance governor)"
    },
    {
      "id": "docker",
      "status": "pending",
      "timestamp": null,
      "task_version_ran": null,
      "description": null
    }
  ]
}
```

`status` ∈ `{completed, failed, pending}`.

## `pi-optimiser --report --output json`

Current-state snapshot. Runtime values are pulled from
`vcgencmd` when available.

```json
{
  "generated_at": "2026-04-20T10:03:37+02:00",
  "system": {
    "model": "Raspberry Pi 5 Model B Rev 1.1",
    "pi_gen": "5",
    "kernel": "6.18.22-v8-16k+",
    "arch": "aarch64",
    "ram_mb": 8058,
    "firmware": "d04171",
    "boot_device": "sdcard"
  },
  "runtime": {
    "throttled": "0x0",
    "soc_temp": "49.4'C"
  },
  "schema_version": 2,
  "task_summary": {
    "total": 48,
    "completed": 7,
    "failed": 0,
    "pending": 41
  },
  "reboot_required": false,
  "reboot_reason": null
}
```

## `pi-optimiser --check-update --output json`

```json
{
  "ref": "master",
  "remote_sha": "5f079dae9efe2d69d4458e93b5e0aff01c0036e8",
  "installed_sha": "5f079dae9efe2d69d4458e93b5e0aff01c0036e8",
  "update_available": false
}
```

Exit codes:

- **0** — up to date
- **10** — update available
- **1** — error (network, parse, etc.)

## `pi-optimiser --list-profiles --output json`

```json
{
  "profiles": [
    {
      "name": "kiosk",
      "enables": ["INSTALL_ZRAM", "WIFI_POWERSAVE_OFF", "SECURE_SSH",
                  "QUIET_BOOT"]
    },
    {
      "name": "server",
      "enables": ["INSTALL_ZRAM", "SECURE_SSH", "INSTALL_SMARTMONTOOLS",
                  "INSTALL_NODE_EXPORTER", "ENABLE_DNS_CACHE",
                  "INSTALL_FIREWALL", "DISABLE_LEDS",
                  "KEEP_SCREEN_BLANKING"]
    },
    {
      "name": "desktop",
      "enables": ["INSTALL_CLI_MODERN"]
    },
    {
      "name": "headless-iot",
      "enables": ["INSTALL_WATCHDOG", "DISABLE_BLUETOOTH",
                  "WIFI_POWERSAVE_OFF", "REQUEST_UNDERCLOCK",
                  "DISABLE_LEDS", "QUIET_BOOT",
                  "KEEP_SCREEN_BLANKING"]
    }
  ]
}
```

## `pi-optimiser --show-config --output json`

The merged (CLI ∘ YAML ∘ defaults) config state. Useful for
debugging precedence and for configuration-management scripts that
want to inspect the live state before deciding to re-apply.

```json
{
  "runtime": {
    "dry_run": false,
    "force": false,
    "profile": "server"
  },
  "integrations": {
    "tailscale": false,
    "wireguard": false,
    "docker": {"enabled": true, "buildx_multiarch": false, "cgroup_v2": false},
    "zram": {"enabled": true, "algo": "lz4"},
    "proxy_backend": null,
    "node_exporter": true,
    "smartmontools": true,
    "cli_modern": false,
    "net_diag": false,
    "dns_cache": true
  },
  "hardware": {
    "overclock_conservative": false,
    "underclock": false,
    "pi5_fan_profile": false,
    "pcie_gen3": false,
    "watchdog": false,
    "wifi_powersave_off": false,
    "disable_bluetooth": false
  },
  "firmware": {"firmware_update": false, "eeprom_update": false},
  "security": {"secure_ssh": true, "ssh_import_github": null, "ssh_import_url": null},
  "system": {"hostname": null, "timezone": null, "locale": null, "keep_screen_blanking": true},
  "metrics": {"enabled": true, "path": null},
  "watch": false,
  "diff_preview": false,
  "freeze_tasks": null
}
```

`metrics`, `watch`, `diff_preview`, `freeze_tasks` were added in
9.1.0. `freeze_tasks` is an array of task ids (or `null`) matching
the names in `--list-tasks`.

The pi-optimiser-owned YAML fields under `integrations.*`,
`hardware.*`, `firmware.*`, `security.*`, `system.*`, and the
top-level `metrics` / `freeze_tasks` / `allow_both_vpn` keys all
round-trip through `pi_config_save` and `pi_config_load`.

## `/etc/pi-optimiser/state.json`

Direct state file (not an `--output json` command). Consumed by
`is_task_done`, `--status`, and `--undo`.

```json
{
  "schema_version": 2,
  "tasks": {
    "cpu_governor": {
      "status": "completed",
      "timestamp": "2026-04-19T10:54:14+02:00",
      "description": "Keep the CPU at full speed (performance governor)",
      "task_version": "1.1.0"
    }
  },
  "reboot": {
    "required": "true",
    "reason": "boot_config",
    "set_at": "2026-04-19T10:54:14+02:00"
  },
  "firewall": {
    "ufw": "enabled",
    "ssh_port": "22",
    "fingerprint": "ssh=22;tailscale;proxy"
  }
}
```

- `tasks.<id>` keys match `lib/tasks/<id>.sh::pi_task_register`.
- `reboot.required` is the string `"true"` / `"false"` (the writer
  is shell, not Python — it's not a JSON boolean).
- `firewall.fingerprint` (9.2.1+) is the hash of inputs that drove
  the last UFW reconcile — SSH port, live VPN interfaces, proxy
  state. The main loop compares it against the current fingerprint
  and reruns `ufw_firewall` when they differ. See
  [`lib/tasks/ufw_firewall.sh`](../lib/tasks/ufw_firewall.sh).
- Arbitrary per-task fields are written by `write_json_field`
  (e.g. `docker.buildx_multiarch`, `overclock.profile`). These are
  informational only; don't treat their shape as schema-stable.

## Prometheus textfile output (9.1.0+)

Written by `lib/features/metrics.sh::pi_metrics_write` at end of
every non-dry-run pass. Target path, in priority order:

1. `$PI_METRICS_PATH` — explicit override (`--metrics-path` or
   `metrics.path:` in YAML).
2. `/var/lib/node_exporter/textfile_collector/pi-optimiser.prom`
   if the directory exists (`prometheus-node-exporter` default).
3. `/etc/pi-optimiser/metrics/pi-optimiser.prom` — fallback.

Format follows the Prometheus
[textfile exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).

```
# HELP pi_optimiser_task_status Per-task status from the most recent run.
# TYPE pi_optimiser_task_status gauge
pi_optimiser_task_status{task="fstab",status="completed"} 1
pi_optimiser_task_status{task="docker",status="skipped"} 1
# HELP pi_optimiser_tasks_completed_total Tasks completed in the most recent run.
# TYPE pi_optimiser_tasks_completed_total gauge
pi_optimiser_tasks_completed_total 7
# HELP pi_optimiser_tasks_failed_total Tasks failed in the most recent run.
# TYPE pi_optimiser_tasks_failed_total gauge
pi_optimiser_tasks_failed_total 0
# HELP pi_optimiser_tasks_skipped_total Tasks skipped in the most recent run.
# TYPE pi_optimiser_tasks_skipped_total gauge
pi_optimiser_tasks_skipped_total 41
# HELP pi_optimiser_last_run_timestamp_seconds Unix time of the most recent run.
# TYPE pi_optimiser_last_run_timestamp_seconds gauge
pi_optimiser_last_run_timestamp_seconds 1776611893
# HELP pi_optimiser_reboot_required 1 if the most recent run flagged a reboot.
# TYPE pi_optimiser_reboot_required gauge
pi_optimiser_reboot_required 0
# HELP pi_optimiser_version_info Installed pi-optimiser version.
# TYPE pi_optimiser_version_info gauge
pi_optimiser_version_info{version="9.2.1"} 1
```

Disable with `--no-metrics` or `metrics.enabled: false`.

## Stability guarantees

- Field additions are non-breaking within a schema version. Consumers
  should ignore unknown keys.
- Field removals or renames require a `schema_version` bump and a
  corresponding entry in `lib/util/state.sh`'s migration table.
- `null` is used for "not yet recorded" (never the empty string).
- `order` in `--status` reflects the task execution order from
  `lib/MANIFEST` at the time the command ran.
- Prometheus metric names and label keys are fixed. New metrics may
  be added; existing ones won't be renamed inside schema v2.
