# shellcheck disable=SC2034
# ======================================================================
# lib/util/config_yaml.sh — /etc/pi-optimiser/config.yaml round-trip
#
# Functions: pi_config_save, pi_config_load
#
# The YAML file is the persistent form of the CLI flag state, so TUI
# sessions can be re-played non-interactively with:
#   sudo pi-optimiser --config /etc/pi-optimiser/config.yaml --no-tui
# CLI flags always override on-disk values. Layout:
#   version: 1
#   profile: <name or custom>
#   integrations: { tailscale: bool, docker: bool, zram: {enabled, algo}, proxy_backend }
#   hardware: { overclock_conservative, pi5_fan_profile, ... }
#   security: { secure_ssh, ssh_import_github, ssh_import_url }
#   system:   { hostname, timezone, locale, keep_screen_blanking }
# ======================================================================

PI_CONFIG_DEFAULT="/etc/pi-optimiser/config.yaml"

pi_config_save() {
  local path=${1:-$PI_CONFIG_DEFAULT}
  mkdir -p "$(dirname "$path")"
  PI_CONFIG_PATH="$path" \
  PI_PROFILE_VAL="${PI_PROFILE:-custom}" \
  V_TAILSCALE="${INSTALL_TAILSCALE:-0}" \
  V_DOCKER="${INSTALL_DOCKER:-0}" \
  V_DOCKER_BUILDX="${DOCKER_BUILDX_MULTIARCH:-0}" \
  V_DOCKER_CGV2="${DOCKER_CGROUPV2:-0}" \
  V_WIREGUARD="${INSTALL_WIREGUARD:-0}" \
  V_ZRAM="${INSTALL_ZRAM:-0}" \
  V_ZRAM_ALGO="${ZRAM_ALGO_OVERRIDE:-}" \
  V_NODE_EXPORTER="${INSTALL_NODE_EXPORTER:-0}" \
  V_SMARTMON="${INSTALL_SMARTMONTOOLS:-0}" \
  V_CLI_MODERN="${INSTALL_CLI_MODERN:-0}" \
  V_NET_DIAG="${INSTALL_NET_DIAG:-0}" \
  V_DNS_CACHE="${ENABLE_DNS_CACHE:-0}" \
  V_OC="${REQUEST_OC_CONSERVATIVE:-0}" \
  V_UNDERCLOCK="${REQUEST_UNDERCLOCK:-0}" \
  V_WATCHDOG="${INSTALL_WATCHDOG:-0}" \
  V_PI5FAN="${INSTALL_PI5_FAN_PROFILE:-0}" \
  V_PCIE3="${INSTALL_PCIE_GEN3:-0}" \
  V_TEMP_LIMIT="${TEMP_LIMIT:-}" \
  V_TEMP_SOFT="${TEMP_SOFT_LIMIT:-}" \
  V_TURBO="${INITIAL_TURBO:-}" \
  V_WIFI="${WIFI_POWERSAVE_OFF:-0}" \
  V_DISBT="${DISABLE_BLUETOOTH:-0}" \
  V_FW_UPDATE="${FIRMWARE_UPDATE:-0}" \
  V_EEPROM="${EEPROM_UPDATE:-0}" \
  V_SECURE_SSH="${SECURE_SSH:-0}" \
  V_GH="${SSH_IMPORT_GITHUB:-}" \
  V_URL="${SSH_IMPORT_URL:-}" \
  V_HOSTNAME="${REQUESTED_HOSTNAME:-}" \
  V_TZ="${REQUESTED_TIMEZONE:-}" \
  V_LOCALE="${REQUESTED_LOCALE:-}" \
  V_KEEP_BLANK="${KEEP_SCREEN_BLANKING:-0}" \
  V_PROXY="${PROXY_BACKEND:-}" \
  run_python <<'PY'
import os
from pathlib import Path

def b(name): return "true" if os.environ.get(name, "0") == "1" else "false"
def s(name): return os.environ.get(name, "") or ""

path = Path(os.environ["PI_CONFIG_PATH"])
lines = []
lines.append("# pi-optimiser config — edit with `sudo pi-optimiser --tui` or by hand.")
lines.append("version: 1")
lines.append(f'profile: {s("PI_PROFILE_VAL") or "custom"}')
lines.append("integrations:")
lines.append(f'  tailscale: {b("V_TAILSCALE")}')
lines.append(f'  wireguard: {b("V_WIREGUARD")}')
lines.append("  docker:")
lines.append(f'    enabled: {b("V_DOCKER")}')
lines.append(f'    buildx_multiarch: {b("V_DOCKER_BUILDX")}')
lines.append(f'    cgroup_v2: {b("V_DOCKER_CGV2")}')
lines.append("  zram:")
lines.append(f'    enabled: {b("V_ZRAM")}')
lines.append(f'    algo: {s("V_ZRAM_ALGO") or "lz4"}')
lines.append(f'  proxy_backend: "{s("V_PROXY")}"')
lines.append(f'  node_exporter: {b("V_NODE_EXPORTER")}')
lines.append(f'  smartmontools: {b("V_SMARTMON")}')
lines.append(f'  cli_modern: {b("V_CLI_MODERN")}')
lines.append(f'  net_diag: {b("V_NET_DIAG")}')
lines.append(f'  dns_cache: {b("V_DNS_CACHE")}')
lines.append("hardware:")
lines.append(f'  overclock_conservative: {b("V_OC")}')
lines.append(f'  underclock: {b("V_UNDERCLOCK")}')
lines.append(f'  pi5_fan_profile: {b("V_PI5FAN")}')
lines.append(f'  pcie_gen3: {b("V_PCIE3")}')
lines.append(f'  watchdog: {b("V_WATCHDOG")}')
lines.append(f'  temp_limit: "{s("V_TEMP_LIMIT")}"')
lines.append(f'  temp_soft_limit: "{s("V_TEMP_SOFT")}"')
lines.append(f'  initial_turbo: "{s("V_TURBO")}"')
lines.append(f'  wifi_powersave_off: {b("V_WIFI")}')
lines.append(f'  disable_bluetooth: {b("V_DISBT")}')
lines.append("firmware:")
lines.append(f'  firmware_update: {b("V_FW_UPDATE")}')
lines.append(f'  eeprom_update: {b("V_EEPROM")}')
lines.append("security:")
lines.append(f'  secure_ssh: {b("V_SECURE_SSH")}')
lines.append(f'  ssh_import_github: "{s("V_GH")}"')
lines.append(f'  ssh_import_url: "{s("V_URL")}"')
lines.append("system:")
lines.append(f'  hostname: "{s("V_HOSTNAME")}"')
lines.append(f'  timezone: "{s("V_TZ")}"')
lines.append(f'  locale: "{s("V_LOCALE")}"')
lines.append(f'  keep_screen_blanking: {b("V_KEEP_BLANK")}')

path.write_text("\n".join(lines) + "\n")
os.chmod(path, 0o644)
PY
}

# pi_config_load <path>: parse a YAML config file and emit bash assignments
# for the globals it maps to. Caller must eval the output.
pi_config_load() {
  local path=${1:-$PI_CONFIG_DEFAULT}
  if [[ ! -f "$path" ]]; then
    log_warn "Config file not found: $path"
    return 1
  fi
  local script
  script=$(PI_CONFIG_PATH="$path" run_python <<'PY'
import os, sys
path = os.environ["PI_CONFIG_PATH"]
# Tiny YAML parser — handles the flat subset we emit. We avoid PyYAML
# since Pi OS doesn't ship it by default.
def parse(text):
    # Stack always retains a sentinel (-1, root) so top-level keys find
    # their parent without popping the root off. Without the sentinel
    # a sibling-at-indent-0 after the first nested block collapses into
    # the wrong dict.
    root = {}
    stack = [(-1, root)]
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        key, _, val = line.strip().partition(":")
        val = val.strip()
        # Strip trailing inline comments: `key: value  # comment` →
        # `key: value`. Quoted strings keep any `#` they contain.
        if val.startswith("\"") and val.endswith("\"") and len(val) >= 2:
            val = val[1:-1]
        else:
            # Look for ` #` or a leading `#` as the comment marker.
            for pos, ch in enumerate(val):
                if ch == "#" and (pos == 0 or val[pos-1] in (" ", "\t")):
                    val = val[:pos].rstrip()
                    break
        # Pop scopes whose indent is >= ours (they're closed now).
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if val == "":
            child = {}
            parent[key.strip()] = child
            stack.append((indent, child))
        else:
            parent[key.strip()] = val
    return root

try:
    data = parse(open(path).read())
except Exception as e:
    print(f"echo 'pi-optimiser: failed to parse {path}: {e}' >&2; return 1", file=sys.stdout)
    sys.exit(0)

import shlex

def bv(value): return "1" if str(value).lower() in ("true","1","yes","on") else "0"
# sv() shell-quotes its argument so malicious values can't break out of
# the assignment and trigger arbitrary execution when bash evals the
# emitted script. Without this, a YAML value like `x"; id; echo "y`
# would run `id` as root.
def sv(value): return shlex.quote(str(value))

def get(d, *keys, default=""):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur

out = []
i = data.get("integrations", {})
out.append(f'INSTALL_TAILSCALE={bv(get(i, "tailscale"))}')
out.append(f'INSTALL_WIREGUARD={bv(get(i, "wireguard"))}')
docker = get(i, "docker", default={})
out.append(f'INSTALL_DOCKER={bv(get(docker, "enabled"))}')
out.append(f'DOCKER_BUILDX_MULTIARCH={bv(get(docker, "buildx_multiarch"))}')
out.append(f'DOCKER_CGROUPV2={bv(get(docker, "cgroup_v2"))}')
zram = get(i, "zram", default={})
out.append(f'INSTALL_ZRAM={bv(get(zram, "enabled"))}')
algo = get(zram, "algo", default="")
if algo and algo != "lz4":
    out.append(f'ZRAM_ALGO_OVERRIDE={sv(algo)}')
out.append(f'PROXY_BACKEND={sv(get(i, "proxy_backend"))}')
out.append(f'INSTALL_NODE_EXPORTER={bv(get(i, "node_exporter"))}')
out.append(f'INSTALL_SMARTMONTOOLS={bv(get(i, "smartmontools"))}')
out.append(f'INSTALL_CLI_MODERN={bv(get(i, "cli_modern"))}')
out.append(f'INSTALL_NET_DIAG={bv(get(i, "net_diag"))}')
out.append(f'ENABLE_DNS_CACHE={bv(get(i, "dns_cache"))}')

h = data.get("hardware", {})
out.append(f'REQUEST_OC_CONSERVATIVE={bv(get(h, "overclock_conservative"))}')
out.append(f'REQUEST_UNDERCLOCK={bv(get(h, "underclock"))}')
out.append(f'INSTALL_PI5_FAN_PROFILE={bv(get(h, "pi5_fan_profile"))}')
out.append(f'INSTALL_PCIE_GEN3={bv(get(h, "pcie_gen3"))}')
out.append(f'INSTALL_WATCHDOG={bv(get(h, "watchdog"))}')
out.append(f'WIFI_POWERSAVE_OFF={bv(get(h, "wifi_powersave_off"))}')
out.append(f'DISABLE_BLUETOOTH={bv(get(h, "disable_bluetooth"))}')
for v in ("temp_limit", "temp_soft_limit", "initial_turbo"):
    val = get(h, v)
    if val:
        var = {"temp_limit":"TEMP_LIMIT","temp_soft_limit":"TEMP_SOFT_LIMIT","initial_turbo":"INITIAL_TURBO"}[v]
        out.append(f'{var}={sv(val)}; THERMAL_THRESHOLDS_SET=1')

f = data.get("firmware", {})
out.append(f'FIRMWARE_UPDATE={bv(get(f, "firmware_update"))}')
out.append(f'EEPROM_UPDATE={bv(get(f, "eeprom_update"))}')

s = data.get("security", {})
out.append(f'SECURE_SSH={bv(get(s, "secure_ssh"))}')
out.append(f'SSH_IMPORT_GITHUB={sv(get(s, "ssh_import_github"))}')
out.append(f'SSH_IMPORT_URL={sv(get(s, "ssh_import_url"))}')

sy = data.get("system", {})
out.append(f'REQUESTED_HOSTNAME={sv(get(sy, "hostname"))}')
out.append(f'REQUESTED_TIMEZONE={sv(get(sy, "timezone"))}')
out.append(f'REQUESTED_LOCALE={sv(get(sy, "locale"))}')
out.append(f'KEEP_SCREEN_BLANKING={bv(get(sy, "keep_screen_blanking"))}')

# Prometheus metrics opt-in + optional path override.
m = data.get("metrics", {})
if isinstance(m, dict):
    enabled = get(m, "enabled", default="")
    if str(enabled).lower() in ("false", "0", "no", "off"):
        out.append('PI_METRICS_ENABLED=0')
    mpath = get(m, "path")
    if mpath:
        out.append(f'PI_METRICS_PATH={sv(mpath)}')

# Per-task freeze: `freeze_tasks: [id1, id2]` or nested list form.
# Supports both inline `[a, b]` and multi-line `- a` YAML styles; our
# tiny parser flattens multi-line lists into a single `- a - b` string
# so we split on both commas and `- ` markers.
frozen = data.get("freeze_tasks", "")
if isinstance(frozen, str) and frozen:
    import re
    raw = frozen.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    parts = re.split(r"[,\s]+", raw.replace("-", " "))
    ids = [p.strip().strip('"\'') for p in parts if p.strip()]
    for fid in ids:
        if re.match(r"^[a-z0-9_]+$", fid):
            out.append(f'PI_FROZEN_TASKS[{sv(fid)}]=1')

print("\n".join(out))
PY
  ) || return 1
  # The emitted script contains only `VAR='shell-quoted value'` lines,
  # so eval is safe despite its reputation.
  # shellcheck disable=SC2086
  eval "$script"
  log_info "Loaded config from $path"
}
