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
  local _frozen_ids=""
  if declare -p PI_FROZEN_TASKS >/dev/null 2>&1 && (( ${#PI_FROZEN_TASKS[@]} > 0 )); then
    _frozen_ids="${!PI_FROZEN_TASKS[*]}"
  fi
  mkdir -p "$(dirname "$path")"
  PI_CONFIG_PATH="$path" \
  PI_PROFILE_VAL="${PI_PROFILE:-custom}" \
  V_TAILSCALE="${INSTALL_TAILSCALE:-0}" \
  V_DOCKER="${INSTALL_DOCKER:-0}" \
  V_DOCKER_BUILDX="${DOCKER_BUILDX_MULTIARCH:-0}" \
  V_DOCKER_CGV2="${DOCKER_CGROUPV2:-0}" \
  V_WIREGUARD="${INSTALL_WIREGUARD:-0}" \
  V_ALLOW_BOTH_VPN="${ALLOW_BOTH_VPN:-0}" \
  V_ZRAM="${INSTALL_ZRAM:-0}" \
  V_ZRAM_ALGO="${ZRAM_ALGO_OVERRIDE:-}" \
  V_NODE_EXPORTER="${INSTALL_NODE_EXPORTER:-0}" \
  V_SMARTMON="${INSTALL_SMARTMONTOOLS:-0}" \
  V_CLI_MODERN="${INSTALL_CLI_MODERN:-0}" \
  V_NET_DIAG="${INSTALL_NET_DIAG:-0}" \
  V_DNS_CACHE="${ENABLE_DNS_CACHE:-0}" \
  V_PI_CONNECT="${INSTALL_PI_CONNECT:-0}" \
  V_HAILO="${INSTALL_HAILO:-0}" \
  V_CHRONY="${INSTALL_CHRONY:-0}" \
  V_DISABLE_IPV6="${DISABLE_IPV6:-0}" \
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
  V_QUIET_BOOT="${QUIET_BOOT:-0}" \
  V_DISABLE_LEDS="${DISABLE_LEDS:-0}" \
  V_NVME_TUNE="${NVME_TUNE:-0}" \
  V_HEADLESS_GPU="${HEADLESS_GPU_MEM:-0}" \
  V_USB_UAS="${USB_UAS_QUIRKS:-0}" \
  V_USB_UAS_EXTRA="${USB_UAS_EXTRA:-}" \
  V_FW_UPDATE="${FIRMWARE_UPDATE:-0}" \
  V_EEPROM="${EEPROM_UPDATE:-0}" \
  V_POWER_OFF_HALT="${POWER_OFF_HALT:-0}" \
  V_SECURE_SSH="${SECURE_SSH:-0}" \
  V_FIREWALL="${INSTALL_FIREWALL:-0}" \
  V_GH="${SSH_IMPORT_GITHUB:-}" \
  V_URL="${SSH_IMPORT_URL:-}" \
  V_HOSTNAME="${REQUESTED_HOSTNAME:-}" \
  V_TZ="${REQUESTED_TIMEZONE:-}" \
  V_LOCALE="${REQUESTED_LOCALE:-}" \
  V_KEEP_BLANK="${KEEP_SCREEN_BLANKING:-0}" \
  V_REMOVE_CUPS="${REMOVE_CUPS:-0}" \
  V_PROXY="${PROXY_BACKEND:-}" \
  V_METRICS_ENABLED="${PI_METRICS_ENABLED:-1}" \
  V_METRICS_PATH="${PI_METRICS_PATH:-}" \
  V_FROZEN="$_frozen_ids" \
  run_python <<'PY'
import os
from pathlib import Path

def b(name): return "true" if os.environ.get(name, "0") == "1" else "false"
def s(name):
    # Backward-compat: older loaders could round-trip empty scalars as
    # literal "{}". Treat that legacy sentinel as unset on save.
    v = os.environ.get(name, "") or ""
    if v in ("{}", "null", "None"):
        return ""
    return v

path = Path(os.environ["PI_CONFIG_PATH"])
lines = []
lines.append("# pi-optimiser config — edit with `sudo pi-optimiser --tui` or by hand.")
lines.append("version: 1")
lines.append(f'profile: {s("PI_PROFILE_VAL") or "custom"}')
lines.append("integrations:")
lines.append(f'  tailscale: {b("V_TAILSCALE")}')
lines.append(f'  wireguard: {b("V_WIREGUARD")}')
lines.append(f'  allow_both_vpn: {b("V_ALLOW_BOTH_VPN")}')
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
lines.append(f'  pi_connect: {b("V_PI_CONNECT")}')
lines.append(f'  hailo: {b("V_HAILO")}')
lines.append(f'  chrony: {b("V_CHRONY")}')
lines.append(f'  disable_ipv6: {b("V_DISABLE_IPV6")}')
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
lines.append(f'  quiet_boot: {b("V_QUIET_BOOT")}')
lines.append(f'  disable_leds: {b("V_DISABLE_LEDS")}')
lines.append(f'  nvme_tune: {b("V_NVME_TUNE")}')
lines.append(f'  headless_gpu_mem: {b("V_HEADLESS_GPU")}')
lines.append(f'  usb_uas_quirks: {b("V_USB_UAS")}')
lines.append(f'  usb_uas_extra: "{s("V_USB_UAS_EXTRA")}"')
lines.append("firmware:")
lines.append(f'  firmware_update: {b("V_FW_UPDATE")}')
lines.append(f'  eeprom_update: {b("V_EEPROM")}')
lines.append(f'  power_off_halt: {b("V_POWER_OFF_HALT")}')
lines.append("security:")
lines.append(f'  secure_ssh: {b("V_SECURE_SSH")}')
lines.append(f'  firewall: {b("V_FIREWALL")}')
lines.append(f'  ssh_import_github: "{s("V_GH")}"')
lines.append(f'  ssh_import_url: "{s("V_URL")}"')
lines.append("system:")
lines.append(f'  hostname: "{s("V_HOSTNAME")}"')
lines.append(f'  timezone: "{s("V_TZ")}"')
lines.append(f'  locale: "{s("V_LOCALE")}"')
lines.append(f'  keep_screen_blanking: {b("V_KEEP_BLANK")}')
lines.append(f'  remove_cups: {b("V_REMOVE_CUPS")}')
lines.append("metrics:")
lines.append(f'  enabled: {b("V_METRICS_ENABLED")}')
lines.append(f'  path: "{s("V_METRICS_PATH")}"')
frozen = sorted(x for x in os.environ.get("V_FROZEN", "").split() if x)
if frozen:
    lines.append("freeze_tasks: [" + ", ".join(frozen) + "]")
else:
    lines.append("freeze_tasks: []")

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
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # List items (`- foo`) are accepted only as direct children of a
        # map key that already opened a block (e.g. `freeze_tasks:` then
        # `- fstab`). Keep the legacy behaviour: they're stored as keys
        # of the current dict so the downstream consumer can read them
        # via `isinstance(frozen, dict)`.
        if stripped.startswith("- ") or stripped == "-":
            indent = len(line) - len(line.lstrip())
            while stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1]
            if isinstance(parent, dict):
                parent[stripped] = ""
            continue
        # Every non-list line must be `key: value` or `key:` — reject
        # anything missing the colon so a malformed YAML like
        # `version 1` (missing `:`) fails loudly instead of silently
        # landing as an empty nested dict under key "version 1".
        if ":" not in stripped:
            raise ValueError(
                f"line {lineno}: missing ':' separator: {stripped!r}")
        indent = len(line) - len(line.lstrip())
        key, _, val = stripped.partition(":")
        val = val.strip()
        # Distinguish `key:` (map block) from explicit empty scalars like
        # `key: ""` or `key: # comment`, which must stay strings.
        has_rhs_token = (val != "")
        # Reject unbalanced quotes before any stripping. An odd number
        # of unescaped double- or single-quotes means the value ran off
        # the end of the line (or has stray quotes in it) — either way,
        # not something the round-trip writer would ever produce.
        if val.count('"') % 2 != 0 or val.count("'") % 2 != 0:
            raise ValueError(
                f"line {lineno}: unbalanced quote in value: {val!r}")
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
        if val == "" and not has_rhs_token:
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

import re
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

def get_str(d, *keys, default=""):
    v = get(d, *keys, default=default)
    if isinstance(v, dict):
        return default
    s = str(v)
    # Backward-compat: prior parser versions converted empty quoted
    # strings to dicts, which then saved as literal "{}".
    if s in ("{}", "null", "None"):
        return default
    return s

def valid_metrics_path(path):
    return (
        path.startswith("/")
        and path.endswith(".prom")
        and not re.search(r"[\s\0-\037`\\'\";|<>(){}]", path)
        and "/../" not in path
        and not path.endswith("/..")
        and "/./" not in path
    )

def valid_usb_uas_list(value):
    return re.match(
        r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}(:[a-z]+)?"
        r"(,[0-9a-fA-F]{4}:[0-9a-fA-F]{4}(:[a-z]+)?)*$",
        value,
    ) is not None

out = []
def has(d, *keys):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return False
    return True

def emit_bool(var, d, *keys):
    if has(d, *keys):
        out.append(f'{var}={bv(get(d, *keys))}')

def emit_str(var, d, *keys):
    if has(d, *keys):
        out.append(f'{var}={sv(get_str(d, *keys))}')

profile = get_str(data, "profile")
if profile:
    allowed_profiles = {"kiosk", "server", "desktop", "headless-iot", "custom"}
    if profile not in allowed_profiles:
        out.append(f'echo {sv("pi-optimiser: unknown profile in config: " + profile)} >&2')
        out.append("return 1")
    else:
        out.append(f'PI_PROFILE={sv(profile)}')
        if profile != "custom":
            out.append('if declare -F pi_apply_profile >/dev/null 2>&1; then pi_apply_profile "$PI_PROFILE" >/dev/null; fi')

i = data.get("integrations", {})
emit_bool("INSTALL_TAILSCALE", i, "tailscale")
emit_bool("INSTALL_WIREGUARD", i, "wireguard")
emit_bool("ALLOW_BOTH_VPN", i, "allow_both_vpn")
docker = get(i, "docker", default={})
emit_bool("INSTALL_DOCKER", docker, "enabled")
emit_bool("DOCKER_BUILDX_MULTIARCH", docker, "buildx_multiarch")
emit_bool("DOCKER_CGROUPV2", docker, "cgroup_v2")
zram = get(i, "zram", default={})
emit_bool("INSTALL_ZRAM", zram, "enabled")
if has(zram, "algo"):
    algo = get_str(zram, "algo", default="")
    if algo and algo != "lz4":
        out.append(f'ZRAM_ALGO_OVERRIDE={sv(algo)}')
    elif algo == "lz4":
        out.append('ZRAM_ALGO_OVERRIDE=""')
emit_str("PROXY_BACKEND", i, "proxy_backend")
emit_bool("INSTALL_NODE_EXPORTER", i, "node_exporter")
emit_bool("INSTALL_SMARTMONTOOLS", i, "smartmontools")
emit_bool("INSTALL_CLI_MODERN", i, "cli_modern")
emit_bool("INSTALL_NET_DIAG", i, "net_diag")
emit_bool("ENABLE_DNS_CACHE", i, "dns_cache")
emit_bool("INSTALL_PI_CONNECT", i, "pi_connect")
emit_bool("INSTALL_HAILO", i, "hailo")
emit_bool("INSTALL_CHRONY", i, "chrony")
emit_bool("DISABLE_IPV6", i, "disable_ipv6")

h = data.get("hardware", {})
emit_bool("REQUEST_OC_CONSERVATIVE", h, "overclock_conservative")
emit_bool("REQUEST_UNDERCLOCK", h, "underclock")
emit_bool("INSTALL_PI5_FAN_PROFILE", h, "pi5_fan_profile")
emit_bool("INSTALL_PCIE_GEN3", h, "pcie_gen3")
emit_bool("INSTALL_WATCHDOG", h, "watchdog")
emit_bool("WIFI_POWERSAVE_OFF", h, "wifi_powersave_off")
emit_bool("DISABLE_BLUETOOTH", h, "disable_bluetooth")
emit_bool("QUIET_BOOT", h, "quiet_boot")
emit_bool("DISABLE_LEDS", h, "disable_leds")
emit_bool("NVME_TUNE", h, "nvme_tune")
emit_bool("HEADLESS_GPU_MEM", h, "headless_gpu_mem")
emit_bool("USB_UAS_QUIRKS", h, "usb_uas_quirks")
_uas_extra = get_str(h, "usb_uas_extra")
if _uas_extra:
    if not valid_usb_uas_list(_uas_extra):
        out.append('echo "pi-optimiser: invalid usb_uas_extra in config" >&2')
        out.append("return 1")
    else:
        out.append(f'USB_UAS_EXTRA={sv(_uas_extra)}; USB_UAS_QUIRKS=1')
for v in ("temp_limit", "temp_soft_limit", "initial_turbo"):
    val = get(h, v)
    if val:
        var = {"temp_limit":"TEMP_LIMIT","temp_soft_limit":"TEMP_SOFT_LIMIT","initial_turbo":"INITIAL_TURBO"}[v]
        out.append(f'{var}={sv(val)}; THERMAL_THRESHOLDS_SET=1')

f = data.get("firmware", {})
emit_bool("FIRMWARE_UPDATE", f, "firmware_update")
emit_bool("EEPROM_UPDATE", f, "eeprom_update")
emit_bool("POWER_OFF_HALT", f, "power_off_halt")

s = data.get("security", {})
emit_bool("SECURE_SSH", s, "secure_ssh")
emit_str("SSH_IMPORT_GITHUB", s, "ssh_import_github")
emit_str("SSH_IMPORT_URL", s, "ssh_import_url")
emit_bool("INSTALL_FIREWALL", s, "firewall")

sy = data.get("system", {})
emit_str("REQUESTED_HOSTNAME", sy, "hostname")
emit_str("REQUESTED_TIMEZONE", sy, "timezone")
emit_str("REQUESTED_LOCALE", sy, "locale")
emit_bool("KEEP_SCREEN_BLANKING", sy, "keep_screen_blanking")
emit_bool("REMOVE_CUPS", sy, "remove_cups")

# Prometheus metrics opt-in + optional path override.
m = data.get("metrics", {})
if isinstance(m, dict):
    enabled = get(m, "enabled", default="")
    if str(enabled).lower() in ("false", "0", "no", "off"):
        out.append('PI_METRICS_ENABLED=0')
    mpath = get_str(m, "path")
    if mpath:
        if not valid_metrics_path(mpath):
            out.append('echo "pi-optimiser: invalid metrics path in config" >&2')
            out.append("return 1")
        else:
            out.append(f'PI_METRICS_PATH={sv(mpath)}')

# Per-task freeze. Supports both inline and multi-line YAML:
#   freeze_tasks: [fstab, zram]         # inline → string "[fstab, zram]"
#   freeze_tasks:                        # multi-line → dict with keys
#     - fstab                            #   "- fstab" and "- zram"
#     - zram                             #   (our tiny parser doesn't grok lists)
frozen_ids = []
frozen = data.get("freeze_tasks", "")
if isinstance(frozen, str) and frozen.strip():
    raw = frozen.strip().lstrip("[").rstrip("]")
    frozen_ids = [p.strip().strip('"\'') for p in raw.split(",")]
elif isinstance(frozen, dict):
    frozen_ids = [k.lstrip("- ").strip() for k in frozen.keys()]
for fid in frozen_ids:
    if re.match(r"^[a-z0-9_]+$", fid):
        out.append(f'PI_FROZEN_TASKS[{sv(fid)}]=1')

print("\n".join(out))
PY
  ) || return 1
  # The emitted script contains only shell-quoted assignments plus
  # trusted framework calls such as pi_apply_profile, so eval is safe
  # despite its reputation.
  local eval_rc=0
  eval "$script" || eval_rc=$?
  if [[ $eval_rc -ne 0 ]]; then
    return "$eval_rc"
  fi
  log_info "Loaded config from $path"
}
