# pi-optimiser JSON output schemas

Every command that accepts `--output json` emits a single JSON object
on stdout. Log lines go to **stderr** so the stdout stream is pure
JSON for `jq` / `python -m json.tool` / other consumers.

All schemas are stable within a schema major version. The
`schema_version` integer (where present) matches
`PI_STATE_SCHEMA_TARGET` in `lib/util/state.sh`; currently **2**.

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
      "description": "Pin CPU scaling governor to performance via systemd"
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
  "generated_at": "2026-04-19T10:03:37+02:00",
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
    "total": 42,
    "completed": 7,
    "failed": 0,
    "pending": 35
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
      "enables": ["INSTALL_ZRAM", "WIFI_POWERSAVE_OFF", "SECURE_SSH"]
    },
    {
      "name": "server",
      "enables": ["INSTALL_ZRAM", "SECURE_SSH", "INSTALL_SMARTMONTOOLS",
                  "INSTALL_NODE_EXPORTER", "ENABLE_DNS_CACHE",
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
                  "KEEP_SCREEN_BLANKING"]
    }
  ]
}
```

## `pi-optimiser --show-config --output json`

Emits the same YAML schema that `pi_config_save` writes to
`/etc/pi-optimiser/config.yaml` (see `lib/util/config_yaml.sh` for
the full layout), but to stdout and not the default path. Intended
for debugging profile + CLI + YAML precedence.

## Stability guarantees

- Field additions are non-breaking within a schema version. Consumers
  should ignore unknown keys.
- Field removals or renames require a `schema_version` bump and a
  corresponding entry in `lib/util/state.sh`'s migration table.
- `null` is used for "not yet recorded" (never the empty string).
- `order` in `--status` reflects the task execution order from
  `lib/MANIFEST` at the time the command ran.
