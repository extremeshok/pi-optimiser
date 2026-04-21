#!/usr/bin/env bash
# ======================================================================
# tests/docker/run-tests.sh — integration-test harness
#
# Run inside the tests/docker/Dockerfile image. Exercises read-only and
# --dry-run code paths that shellcheck alone can't cover. Any failing
# step aborts the script (set -e) so CI surfaces the first break.
# ======================================================================
set -euo pipefail

BIN=${BIN:-/opt/pi-optimiser/pi-optimiser.sh}
cd /opt/pi-optimiser

# Scratch dir for fixture / capture files. Cleaned on any exit so a
# partial run doesn't leave droppings for the next invocation if the
# container is reused (most CI runs get a fresh image, but --rm isn't
# guaranteed when operators poke locally).
TEST_TMP=$(mktemp -d /tmp/pi-optimiser-tests.XXXXXX)
trap 'rm -rf "$TEST_TMP"' EXIT

pass() { printf 'PASS  %s\n' "$1"; }
step() { printf '\n==> %s\n' "$1"; }
fail() {
  # Uniform failure helper: print a message to stderr, dump any
  # captured output tail for context, exit 1. All assertions below
  # use this instead of open-coded `printf FAIL ; exit 1`.
  printf 'FAIL  %s\n' "$1" >&2
  if [[ -n "${2:-}" ]]; then
    printf '%s\n' "$2" | tail -40 >&2
  fi
  exit 1
}

step "syntax: bash -n every shell file"
bash -n "$BIN"
for f in lib/util/*.sh lib/tasks/*.sh lib/features/*.sh lib/ui/*.sh scripts/*.sh install.sh; do
  [[ -f "$f" ]] || continue
  bash -n "$f"
done
pass "bash -n"

step "shellcheck: lib + main + install"
shellcheck --severity=warning --shell=bash \
  "$BIN" lib/util/*.sh lib/tasks/*.sh lib/features/*.sh lib/ui/*.sh \
  scripts/*.sh install.sh
pass "shellcheck"

step "info commands should exit 0"
"$BIN" --version >/dev/null
"$BIN" --help >/dev/null
"$BIN" --list-tasks >/dev/null
"$BIN" --list-profiles >/dev/null
"$BIN" --list-profiles --output json | python3 -m json.tool >/dev/null
pass "info commands"

step "self-test runs without crashing AND reports expected sections"
# Previously this was `--self-test >/dev/null || true` which only
# caught exit code 127 (command not found). We now require the
# self-test banner AND the per-task precondition table so a silent
# crash (exit 0 with empty stdout) cannot pass.
self_test_out=$("$BIN" --self-test 2>&1 || true)
[[ "$self_test_out" == *"pi-optimiser self-test"* ]] \
  || fail "self-test missing header" "$self_test_out"
[[ "$self_test_out" == *"Task preconditions"* ]] \
  || fail "self-test missing task-preconditions table" "$self_test_out"
pass "self-test"

step "--validate-config accepts a known-good YAML"
cat > "$TEST_TMP/good.yaml" <<'YAML'
version: 1
profile: server
integrations:
  tailscale: false
  docker:
    enabled: true
metrics:
  enabled: true
YAML
"$BIN" --validate-config "$TEST_TMP/good.yaml"
pass "validate-config"

step "--validate-config rejects unrelated file"
if "$BIN" --validate-config /etc/hosts 2>/dev/null; then
  fail "expected --validate-config to reject /etc/hosts"
fi
pass "validate-config rejects /etc/hosts"

step "--validate-config rejects malformed YAML"
# A file that *does* carry a recognised top-level key but has broken
# structure (missing colon, unbalanced quote) should be caught. The
# loader either errors or the Python emitter crashes — either way,
# exit code must be non-zero.
cat > "$TEST_TMP/bad.yaml" <<'YAML'
version 1
integrations:
  tailscale: "unterminated
YAML
if "$BIN" --validate-config "$TEST_TMP/bad.yaml" 2>/dev/null; then
  fail "expected --validate-config to reject malformed YAML"
fi
pass "validate-config rejects malformed YAML"

step "config loader keeps explicit empty scalars empty (and heals legacy '{}')"
cat > "$TEST_TMP/empty-scalars.yaml" <<'YAML'
version: 1
integrations:
  proxy_backend: ""
security:
  ssh_import_github: ""
  ssh_import_url: ""
system:
  hostname: ""
  timezone: ""
  locale: ""
YAML
empty_cfg=$("$BIN" --show-config --config "$TEST_TMP/empty-scalars.yaml" --output json 2>/dev/null)
printf '%s' "$empty_cfg" | python3 -c '
import json, sys
cfg = json.loads(sys.stdin.read())
assert cfg["integrations"]["proxy_backend"] is None, cfg["integrations"]["proxy_backend"]
assert cfg["security"]["ssh_import_github"] is None, cfg["security"]["ssh_import_github"]
assert cfg["security"]["ssh_import_url"] is None, cfg["security"]["ssh_import_url"]
assert cfg["system"]["hostname"] is None, cfg["system"]["hostname"]
assert cfg["system"]["timezone"] is None, cfg["system"]["timezone"]
assert cfg["system"]["locale"] is None, cfg["system"]["locale"]
'

cat > "$TEST_TMP/legacy-empty-scalars.yaml" <<'YAML'
version: 1
integrations:
  proxy_backend: "{}"
security:
  ssh_import_github: "{}"
  ssh_import_url: "{}"
system:
  hostname: "{}"
  timezone: "{}"
  locale: "{}"
YAML
legacy_cfg=$("$BIN" --show-config --config "$TEST_TMP/legacy-empty-scalars.yaml" --output json 2>/dev/null)
printf '%s' "$legacy_cfg" | python3 -c '
import json, sys
cfg = json.loads(sys.stdin.read())
assert cfg["integrations"]["proxy_backend"] is None, cfg["integrations"]["proxy_backend"]
assert cfg["security"]["ssh_import_github"] is None, cfg["security"]["ssh_import_github"]
assert cfg["security"]["ssh_import_url"] is None, cfg["security"]["ssh_import_url"]
assert cfg["system"]["hostname"] is None, cfg["system"]["hostname"]
assert cfg["system"]["timezone"] is None, cfg["system"]["timezone"]
assert cfg["system"]["locale"] is None, cfg["system"]["locale"]
'
pass "config loader empty-scalar handling"

step "TUI category preselects previously completed tasks"
tui_capture="$TEST_TMP/tui-category.args"
CAPTURE="$tui_capture" bash -c '
  set -euo pipefail
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/ui/tui.sh
  declare -a PI_TASK_ORDER=(fstab zram)
  declare -A PI_TASK_CATEGORY PI_TASK_DESC PI_TASK_DEFAULT PI_TASK_GATE_VAR
  declare -A PI_TUI_SELECTED PI_TUI_VISITED_CATEGORIES
  PI_TASK_CATEGORY[fstab]="storage"
  PI_TASK_DESC[fstab]="fstab desc"
  PI_TASK_DEFAULT[fstab]=1
  PI_TASK_CATEGORY[zram]="storage"
  PI_TASK_DESC[zram]="zram desc"
  PI_TASK_DEFAULT[zram]=0
  PI_TASK_GATE_VAR[zram]="INSTALL_ZRAM"
  INSTALL_ZRAM=0

  get_task_state() {
    local tid=$1
    if [[ "$tid" == "fstab" ]]; then
      TASK_STATE_STATUS="completed"
      TASK_STATE_TIMESTAMP="2026-04-20T17:42:57+02:00"
      TASK_STATE_DESC="desc"
      TASK_STATE_VERSION="1.1.0"
      return 0
    fi
    return 1
  }

  _whiptail() {
    printf "%s\n" "$@" > "$CAPTURE"
    # whiptail emits selections on stderr.
    printf "\"fstab\"\n" >&2
  }

  _pi_tui_category storage "Storage & filesystems"
  [[ "${PI_TUI_SELECTED[fstab]:-}" == "1" ]]
  [[ -z "${PI_TUI_SELECTED[zram]:-}" ]]

  mapfile -t args < "$CAPTURE"
  found=0
  for ((i=0; i<${#args[@]}; i++)); do
    if [[ "${args[$i]}" == "fstab" ]]; then
      found=1
      [[ "${args[$((i+2))]:-}" == "ON" ]]
      break
    fi
  done
  [[ $found -eq 1 ]]
'
pass "TUI completed-task preselection"

step "TUI proxy form accepts disable sentinels and rejects malformed URLs"
bash -c '
  set -euo pipefail
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/validate.sh
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/ui/tui.sh

  NEXT_INPUT=""
  _whiptail() {
    # _pi_tui_form_proxy uses exactly one inputbox call; any validation
    # failure follows with a msgbox. Feed NEXT_INPUT to inputbox and
    # no-op the rest.
    if [[ "$*" == *"--inputbox"* ]]; then
      printf "%s\n" "$NEXT_INPUT" >&2
    fi
    return 0
  }

  PROXY_BACKEND=""
  NEXT_INPUT="off"
  _pi_tui_form_proxy
  [[ "$PROXY_BACKEND" == "off" ]]

  NEXT_INPUT="NONE"
  _pi_tui_form_proxy
  [[ "$PROXY_BACKEND" == "NONE" ]]

  NEXT_INPUT="http://x.com; id"
  _pi_tui_form_proxy
  # Invalid value should be rejected and must not replace the last
  # accepted backend value.
  [[ "$PROXY_BACKEND" == "NONE" ]]
'
pass "TUI proxy form sentinel/validation parity"

step "TUI apply saves config.yaml and preserves only the selected gates"
CFG="$TEST_TMP/tui-apply.yaml" bash -c '
  set -euo pipefail
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/python.sh
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/config_yaml.sh
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/ui/tui.sh
  log_info() { :; }

  PI_CONFIG_DEFAULT="$CFG"
  declare -a PI_TASK_ORDER=(zram tailscale)
  declare -A PI_TASK_CATEGORY PI_TASK_DESC PI_TASK_DEFAULT PI_TASK_GATE_VAR
  declare -A PI_TUI_SELECTED PI_TUI_VISITED_CATEGORIES

  PI_TASK_CATEGORY[zram]="storage"
  PI_TASK_DESC[zram]="zram desc"
  PI_TASK_DEFAULT[zram]=0
  PI_TASK_GATE_VAR[zram]="INSTALL_ZRAM"

  PI_TASK_CATEGORY[tailscale]="integrations"
  PI_TASK_DESC[tailscale]="tailscale desc"
  PI_TASK_DEFAULT[tailscale]=0
  PI_TASK_GATE_VAR[tailscale]="INSTALL_TAILSCALE"

  PI_TUI_VISITED_CATEGORIES[storage]=1
  PI_TUI_VISITED_CATEGORIES[integrations]=1
  PI_TUI_SELECTED[zram]=1

  INSTALL_ZRAM=0
  INSTALL_TAILSCALE=1
  REQUESTED_HOSTNAME="pi-demo"
  REQUESTED_TIMEZONE="Europe/London"
  REQUESTED_LOCALE="en_GB.UTF-8"
  PROXY_BACKEND="http://127.0.0.1:8080"
  PI_PROFILE="server"

  pi_validate_mutex() { return 0; }
  _whiptail() { return 0; }

  _pi_tui_apply

  [[ ${#ONLY_TASKS[@]} -eq 1 ]]
  [[ "${ONLY_TASKS[0]}" == "zram" ]]
  [[ "${INSTALL_ZRAM:-0}" == "1" ]]
  [[ "${INSTALL_TAILSCALE:-0}" == "0" ]]
  [[ "${PI_TUI_READY_TO_RUN:-0}" -eq 1 ]]
  [[ -f "$CFG" ]]

  INSTALL_ZRAM=0
  INSTALL_TAILSCALE=0
  REQUESTED_HOSTNAME=""
  REQUESTED_TIMEZONE=""
  REQUESTED_LOCALE=""
  PROXY_BACKEND=""
  pi_config_load "$CFG"

  [[ "${INSTALL_ZRAM:-0}" == "1" ]]
  [[ "${INSTALL_TAILSCALE:-0}" == "0" ]]
  [[ "${REQUESTED_HOSTNAME:-}" == "pi-demo" ]]
  [[ "${REQUESTED_TIMEZONE:-}" == "Europe/London" ]]
  [[ "${REQUESTED_LOCALE:-}" == "en_GB.UTF-8" ]]
  [[ "${PROXY_BACKEND:-}" == "http://127.0.0.1:8080" ]]
'
pass "TUI apply auto-saves config.yaml and round-trips selections"

step "snapshot restore accepts safe relative symlinks and extracts cleanly"
bash -c '
  set -euo pipefail
  TEST_ROOT=$(mktemp -d /tmp/pi-optimiser-snapshot.XXXXXX)
  LIVE_ROOT=$(mktemp -d /tmp/pi-optimiser-restore.XXXXXX)
  trap "rm -rf \"$TEST_ROOT\" \"$LIVE_ROOT\"" EXIT

  ARCHIVE_ROOT="${LIVE_ROOT#/}"
  SRC_ROOT="$TEST_ROOT/src/$ARCHIVE_ROOT"
  ARCHIVE="$TEST_ROOT/relative-symlink-ok.tgz"
  MARKER_DIR="$LIVE_ROOT/etc/pi-optimiser"

  mkdir -p "$SRC_ROOT/etc/default" "$MARKER_DIR/backups"
  printf "LANG=en_GB.UTF-8\n" > "$SRC_ROOT/etc/locale.conf"
  ln -s ../locale.conf "$SRC_ROOT/etc/default/locale"
  printf "stale journal\n" > "$MARKER_DIR/backups/stale.json"
  tar -czf "$ARCHIVE" -C "$TEST_ROOT/src" "$ARCHIVE_ROOT"

  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/python.sh
  log_info() { :; }
  log_warn() { :; }
  log_error() { printf "ERROR %s\n" "$*" >&2; }
  PI_NON_INTERACTIVE=1
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/features/snapshot.sh

  pi_restore_snapshot "$ARCHIVE"

  [[ -L "$LIVE_ROOT/etc/default/locale" ]]
  [[ "$(readlink "$LIVE_ROOT/etc/default/locale")" == "../locale.conf" ]]
  grep -qx "LANG=en_GB.UTF-8" "$LIVE_ROOT/etc/locale.conf"
  shopt -s nullglob
  moved=( "$MARKER_DIR"/backups.pre-restore-* )
  shopt -u nullglob
  (( ${#moved[@]} == 1 ))
  [[ ! -d "$MARKER_DIR/backups" ]]
'
pass "snapshot restore handles safe relative symlinks"

step "--show-config text mode includes expected sections"
"$BIN" --show-config --config "$TEST_TMP/good.yaml" >"$TEST_TMP/shown.txt"
grep -q 'Effective pi-optimiser config' "$TEST_TMP/shown.txt"
grep -q 'Framework' "$TEST_TMP/shown.txt"
pass "show-config text"

step "--show-config --output json emits valid JSON with expected keys"
"$BIN" --show-config --config "$TEST_TMP/good.yaml" --output json >"$TEST_TMP/shown.json"
python3 -m json.tool <"$TEST_TMP/shown.json" >/dev/null
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "metrics" in d and "freeze_tasks" in d and "integrations" in d, d.keys()' "$TEST_TMP/shown.json"
pass "show-config JSON"

step "--completion bash / zsh produce usable output"
# Capture stdout; assert a completion-ish substring so an empty
# completion (real regression we shipped in 9.0.2) fails hard.
bash_comp=$("$BIN" --completion bash)
zsh_comp=$("$BIN" --completion zsh)
[[ -n "$bash_comp" ]] || fail "bash completion was empty"
[[ -n "$zsh_comp"  ]] || fail "zsh completion was empty"
# The bash script advertises pi-optimiser; the zsh script starts with
# `#compdef` (or `compdef`). Either way, reject output with no hint
# of being a shell-completion script.
[[ "$bash_comp" == *"pi-optimiser"* ]] \
  || fail "bash completion has no pi-optimiser reference" "$bash_comp"
[[ "$zsh_comp" == *"compdef"* || "$zsh_comp" == *"pi-optimiser"* ]] \
  || fail "zsh completion has no compdef/pi-optimiser marker" "$zsh_comp"
pass "completion"

step "--diff flags accepted; no writes to /boot/firmware AND emits diff output"
# Previously this only checked mtime. A --diff crash that exits
# before touching anything would also leave mtime unchanged and
# trivially pass. We now ALSO capture stdout+stderr and require
# either a diff-preview marker or the "no preview available" line
# for a known task. This catches the silent-crash case.
pre_config_mtime=$(stat -c %Y /boot/firmware/config.txt)
diff_out=$("$BIN" --diff --pi5-fan-profile --yes 2>&1 || true)
post_config_mtime=$(stat -c %Y /boot/firmware/config.txt)
if [[ "$pre_config_mtime" != "$post_config_mtime" ]]; then
  fail "--diff modified /boot/firmware/config.txt (mtime $pre_config_mtime -> $post_config_mtime)"
fi
# The diff feature emits one of these markers per task. We require
# at least one so a crash that exits empty is caught.
if [[ "$diff_out" != *"preview"* && "$diff_out" != *"diff"* && "$diff_out" != *"would run"* ]]; then
  fail "--diff produced no preview/diff/would-run output" "$diff_out"
fi
pass "--diff leaves /boot/firmware untouched and emits diff output"

step "--freeze-task consulted by apply_once"
# Capture the full output instead of piping into grep -q. With
# pipefail, grep's early-exit on first match closes the pipe, the
# producer's subsequent log writes take SIGPIPE (rc 141), and the
# pipeline rc becomes non-zero even though the match succeeded.
freeze_out=$("$BIN" --dry-run --freeze-task fstab 2>&1 || true)
if [[ "$freeze_out" != *"fstab (frozen)"* ]]; then
  fail "expected \"fstab (frozen)\" in output" "$freeze_out"
fi
pass "--freeze-task"

step "--freeze-task rejects unknown ids"
if "$BIN" --freeze-task nonexistent_task --yes 2>/dev/null; then
  fail "expected --freeze-task to reject unknown id"
fi
pass "--freeze-task unknown-id validation"

step "9.2 + 9.3 flags parse and reach their tasks under --dry-run"
# Each flag should produce "[dry-run] <task> would run" when its
# opt-in flag is supplied alongside --only <task>. Anything else
# (unknown flag, gate-not-wired, crash during registration) trips
# this suite.
for pair in \
  "--install-firewall ufw_firewall" \
  "--nvme-tune nvme_tune" \
  "--quiet-boot quiet_boot" \
  "--disable-leds disable_leds" \
  "--install-pi-connect pi_connect" \
  "--power-off-halt power_off_halt" \
  "--headless-gpu-mem headless_gpu_mem" \
  "--install-chrony chrony" \
  "--disable-ipv6 ipv6_disable" \
  "--install-hailo hailo"; do
  flag=${pair% *}
  task=${pair#* }
  out=$("$BIN" --dry-run --only "$task" "$flag" --yes 2>&1 || true)
  if [[ "$out" != *"[dry-run] $task would run"* ]]; then
    fail "$flag did not reach $task in dry-run" "$out"
  fi
done
pass "9.2 + 9.3 opt-in flags route to their tasks"

step "pre-9.2 opt-in flags also reach their tasks under --dry-run"
# Broader coverage over the README's Command-line Flags table so a
# regression that breaks any gate_var wiring is caught. Every pair
# below was cross-referenced against lib/tasks/<id>.sh and the
# pi-optimiser.sh parse_args handlers.
for pair in \
  "--install-tailscale tailscale" \
  "--install-docker docker" \
  "--install-zram zram" \
  "--install-wireguard wireguard" \
  "--install-node-exporter node_exporter" \
  "--install-smartmontools smartmontools" \
  "--install-cli-modern cli_bundle_modern" \
  "--install-net-diag net_diag_bundle" \
  "--enable-dns-cache dns_cache" \
  "--overclock-conservative oc_conservative" \
  "--underclock underclock" \
  "--pi5-fan-profile pi5_fan" \
  "--pcie-gen3 pcie_gen3" \
  "--enable-watchdog watchdog" \
  "--secure-ssh secure_ssh" \
  "--firmware-update firmware_update" \
  "--eeprom-update eeprom_refresh" \
  "--wifi-powersave-off wifi_bt_power"; do
  # --disable-bluetooth is also wired into wifi_bt_power but shares
  # WIFI_POWERSAVE_OFF's gate_var with --wifi-powersave-off, so
  # separate coverage there would be redundant.
  flag=${pair% *}
  task=${pair#* }
  out=$("$BIN" --dry-run --only "$task" "$flag" --yes 2>&1 || true)
  if [[ "$out" != *"[dry-run] $task would run"* ]]; then
    fail "$flag did not reach $task in dry-run" "$out"
  fi
done
pass "pre-9.2 opt-in flags route to their tasks"

step "--usb-uas-extra parses VID:PID list and implies --usb-uas-quirks"
# usb-uas-extra takes an arg; verify the parser accepts the list and
# that supplying it alone (without --usb-uas-quirks) is enough.
out=$("$BIN" --dry-run --only usb_uas_quirks --usb-uas-extra "152d:0578,174c:55aa" --yes 2>&1 || true)
if [[ "$out" != *"[dry-run] usb_uas_quirks would run"* ]]; then
  fail "--usb-uas-extra alone should gate the usb_uas_quirks task" "$out"
fi
pass "--usb-uas-extra implies --usb-uas-quirks"

step "--remove-cups flag wires REMOVE_CUPS and server profile implies cleanup heuristic"
# Two assertions, both real:
#  (a) --remove-cups on its own sets the CUPS purge heuristic path.
#      remove_bloat is default_enabled=1 so --dry-run always reports
#      "would run"; that's not what we care about. What we care
#      about is that `--remove-cups` is parsed and reaches the
#      dry-run run phase without an unknown-flag error.
#  (b) The `server` profile sets keep_screen_blanking=true (which
#      in turn drives _remove_bloat_is_headless to return 0).
out=$("$BIN" --dry-run --only remove_bloat --remove-cups --yes 2>&1 || true)
if [[ "$out" != *"[dry-run] remove_bloat would run"* ]]; then
  fail "--remove-cups did not reach remove_bloat" "$out"
fi
out=$("$BIN" --show-config --profile server --output json 2>/dev/null)
printf '%s' "$out" | python3 -c '
import json, sys
cfg = json.loads(sys.stdin.read())
assert cfg["system"]["keep_screen_blanking"] is True, \
    "server profile should set keep_screen_blanking (drives CUPS purge heuristic)"
' || fail "server profile did not set keep_screen_blanking"
pass "--remove-cups and server-profile CUPS heuristic wired"

step "UFW task refuses to run without --install-firewall"
out=$("$BIN" --dry-run --only ufw_firewall --yes 2>&1 || true)
if [[ "$out" != *"ufw_firewall would skip"* ]]; then
  fail "ufw_firewall should skip without --install-firewall" "$out"
fi
pass "UFW gate-var honoured under --dry-run"

step "gate_var skip messages cover every listed 9.2/9.3 flag"
# Pair of the flag's gate_var and the task id — NO flag given, so
# every task should print its "would skip — <VAR> is unset" line.
# This catches regressions where a new task forgets to declare
# gate_var in pi_task_register (the user-visible symptom is
# "always runs on dry-run", silently losing the opt-in).
for pair in \
  "INSTALL_FIREWALL ufw_firewall" \
  "POWER_OFF_HALT power_off_halt" \
  "NVME_TUNE nvme_tune" \
  "QUIET_BOOT quiet_boot" \
  "DISABLE_LEDS disable_leds" \
  "INSTALL_PI_CONNECT pi_connect" \
  "HEADLESS_GPU_MEM headless_gpu_mem" \
  "INSTALL_CHRONY chrony" \
  "DISABLE_IPV6 ipv6_disable" \
  "USB_UAS_QUIRKS usb_uas_quirks" \
  "INSTALL_HAILO hailo"; do
  gate=${pair% *}
  task=${pair#* }
  out=$("$BIN" --dry-run --only "$task" --yes 2>&1 || true)
  if [[ "$out" != *"$task would skip"* || "$out" != *"$gate"* ]]; then
    fail "$task missing gate_var=$gate skip message" "$out"
  fi
done
pass "every 9.2/9.3 task declares a gate_var the dry-runner sees"

step "flag-coverage: every documented CLI flag is accepted by parse_args"
# Meta-test. Takes every `--flag` mentioned in the README flag table
# and passes it to --help/--version with a dry-run kicker, so an
# unknown/renamed flag shows up immediately. Skips flags that take
# arguments (handled above with realistic values).
# shellcheck disable=SC2016  # single-quoted pattern for grep
declare -a docflags=(
  --force --dry-run --status --list-tasks
  --install-tailscale --install-docker --install-zram
  --overclock-conservative --secure-ssh --firmware-update
  --eeprom-update --enable-watchdog --pi5-fan-profile
  --keep-screen-blanking --no-config --list-profiles --report
  --snapshot --check-update --tui --no-tui --yes
  --non-interactive --allow-both-vpn
  --install-firewall --power-off-halt --nvme-tune --quiet-boot
  --disable-leds --install-pi-connect --remove-cups
  --headless-gpu-mem --install-chrony --disable-ipv6
  --usb-uas-quirks --install-hailo
  --pcie-gen3 --underclock --wifi-powersave-off --disable-bluetooth
  --enable-dns-cache --install-wireguard --install-node-exporter
  --install-smartmontools --install-cli-modern --install-net-diag
  --docker-buildx-multiarch --docker-cgroupv2
  --no-metrics --diff --reboot --show-config
)
for flag in "${docflags[@]}"; do
  # Ask --list-tasks to run after parse_args; any unknown flag
  # errors out at parse_args before the list runs.
  if ! "$BIN" "$flag" --list-tasks >/dev/null 2>&1; then
    # Some of these (e.g. --snapshot, --check-update, --report) do
    # more than list tasks and may fail for unrelated reasons
    # inside a rootless container. Probe --help directly instead:
    # --help always short-circuits, so only a genuine unknown-flag
    # error trips it.
    if ! "$BIN" "$flag" --help >/dev/null 2>&1; then
      fail "parse_args rejected documented flag $flag"
    fi
  fi
done
pass "every documented flag accepted by parse_args"

step "--reboot only triggers for reboot-required tasks from this run"
shutdown_dir="$TEST_TMP/shutdown-bin"
shutdown_log="$TEST_TMP/shutdown.log"
mkdir -p "$shutdown_dir" /etc/pi-optimiser /boot/firmware
cat > "$shutdown_dir/shutdown" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SHUTDOWN_LOG:?}"
exit 0
SH
chmod +x "$shutdown_dir/shutdown"
cat > /etc/pi-optimiser/config-optimisations.json <<'JSON'
{
  "reboot": {
    "reason": "stale-prior-run",
    "required": "true"
  }
}
JSON

: > "$shutdown_log"
reboot_out=$(PATH="$shutdown_dir:$PATH" SHUTDOWN_LOG="$shutdown_log" \
  "$BIN" --force --reboot --only sysctl --yes 2>&1 || true)
[[ ! -s "$shutdown_log" ]] \
  || fail "--reboot used stale persistent reboot state" "$(cat "$shutdown_log")"
[[ "$reboot_out" == *"--reboot set but no task in this run flagged reboot-required; skipping"* ]] \
  || fail "missing stale-reboot skip message" "$reboot_out"

printf '# pi-optimiser test fixture\narm_boost=1\ndtparam=audio=on\n' > /boot/firmware/config.txt
printf 'console=serial0,115200 console=tty1 root=PARTUUID=abc rootwait\n' > /boot/firmware/cmdline.txt
: > "$shutdown_log"
reboot_out=$(PATH="$shutdown_dir:$PATH" SHUTDOWN_LOG="$shutdown_log" \
  "$BIN" --force --reboot --quiet-boot --only quiet_boot --yes 2>&1 || true)
grep -qx -- "-r now pi-optimiser --reboot" "$shutdown_log" \
  || fail "reboot-required task did not invoke shutdown -r now" "$reboot_out"
[[ "$reboot_out" == *"--reboot: rebooting now"* ]] \
  || fail "missing live reboot log line" "$reboot_out"
pass "--reboot ignores stale state and triggers only for this run"

step "hostname/timezone/locale re-run when requested value differs from live system"
# The Docker test container is disposable, so the timezone / locale
# probes can read real /etc files rewritten here. Hostname is probed
# via the hostname(1) binary, which we shadow with a shell function.
mkdir -p /etc/default
printf "Europe/London\n" >/etc/timezone
cat >/etc/default/locale <<'EOF'
LANG=en_GB.UTF-8
LC_ALL=en_GB.UTF-8
EOF
bash -c '
  set -euo pipefail
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/tasks/hostname.sh
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/tasks/timezone.sh
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/tasks/locale.sh

  # --- hostname: shadow hostname(1) so the probe reads our fixture.
  hostname() { printf "pi-current\n"; }
  REQUESTED_HOSTNAME="pi-current"
  pi_hostname_value_changed \
    && { echo "FAIL hostname matching current flagged as changed" >&2; exit 1; }
  REQUESTED_HOSTNAME="pi-new"
  pi_hostname_value_changed \
    || { echo "FAIL hostname differing from current not flagged" >&2; exit 1; }
  REQUESTED_HOSTNAME=""
  pi_hostname_value_changed \
    && { echo "FAIL empty REQUESTED_HOSTNAME flagged as changed" >&2; exit 1; }

  # --- timezone: force the /etc/timezone fallback path by making
  # timedatectl return empty, then rely on the fixture file.
  timedatectl() { return 1; }
  REQUESTED_TIMEZONE="Europe/London"
  pi_timezone_value_changed \
    && { echo "FAIL timezone matching current flagged as changed" >&2; exit 1; }
  REQUESTED_TIMEZONE="America/New_York"
  pi_timezone_value_changed \
    || { echo "FAIL timezone differing from current not flagged" >&2; exit 1; }

  # --- locale: the probe reads /etc/default/locale directly (no
  # systemd call to stub), so the fixture is enough.
  REQUESTED_LOCALE="en_GB.UTF-8"
  pi_locale_value_changed \
    && { echo "FAIL locale matching current flagged as changed" >&2; exit 1; }
  REQUESTED_LOCALE="fr_FR.UTF-8"
  pi_locale_value_changed \
    || { echo "FAIL locale differing from current not flagged" >&2; exit 1; }
'
pass "pi_<id>_value_changed reports correctly for hostname/timezone/locale"

step "idempotency: --dry-run twice produces the same run-plan output"
# Run --dry-run --list-tasks twice and diff. Two runs back-to-back
# should be byte-identical — the registry ordering is
# deterministic, state.json is untouched under --dry-run, and
# tasks don't write files. A regression here surfaces accidental
# ordering changes (hashmap iteration creeping in) or side effects
# in a task's registration phase.
"$BIN" --list-tasks >"$TEST_TMP/run1.txt"
"$BIN" --list-tasks >"$TEST_TMP/run2.txt"
if ! diff -u "$TEST_TMP/run1.txt" "$TEST_TMP/run2.txt" >"$TEST_TMP/run.diff"; then
  fail "--list-tasks not idempotent" "$(cat "$TEST_TMP/run.diff")"
fi
# And do the same for --show-config JSON: effective config should
# be a pure function of (argv + yaml + env), not of previous runs.
"$BIN" --show-config --profile server --output json >"$TEST_TMP/cfg1.json"
"$BIN" --show-config --profile server --output json >"$TEST_TMP/cfg2.json"
if ! diff -u "$TEST_TMP/cfg1.json" "$TEST_TMP/cfg2.json" >"$TEST_TMP/cfg.diff"; then
  fail "--show-config not idempotent across two runs" "$(cat "$TEST_TMP/cfg.diff")"
fi
pass "idempotency: --list-tasks and --show-config are stable across runs"

step "error-path: invalid --profile name exits non-zero"
# Every error path should be tested at least once. This one
# belongs to lib/features/profiles.sh::pi_apply_profile.
if "$BIN" --profile bogus --dry-run --yes 2>/dev/null; then
  fail "expected --profile bogus to exit non-zero"
fi
pass "error-path: unknown profile rejected"

step "validator unit tests (validate_* in lib/util/validate.sh)"
# Source the validator library in a subshell and drive each function
# against known-good / known-bad fixtures. Catches silent regressions
# where a validator is loosened (injection vector returns) or
# over-tightened (a legit IANA zone / locale stops validating).
validator_out=$(bash -c '
  set -u
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/validate.sh
  rc=0
  check() {
    local fn=$1 input=$2 want=$3 got=ok
    "$fn" "$input" || got=fail
    if [[ $got != "$want" ]]; then
      printf "  MISS  %s(%q) got=%s want=%s\n" "$fn" "$input" "$got" "$want" >&2
      rc=1
    fi
  }
  # Hostnames — RFC 1123 label, 1..63 chars
  check validate_hostname "pi5"             ok
  check validate_hostname "a"               ok
  check validate_hostname "pi-5"            ok
  check validate_hostname "UPPER"           ok
  check validate_hostname "bad host"        fail
  check validate_hostname "-leading"        fail
  check validate_hostname "trailing-"       fail
  check validate_hostname "under_score"     fail
  check validate_hostname ""                fail
  # Locales — POSIX ll_CC[.enc][@mod] plus {C, C.UTF-8, POSIX}
  check validate_locale "en_GB.UTF-8"       ok
  check validate_locale "C"                 ok
  check validate_locale "C.UTF-8"           ok
  check validate_locale "POSIX"             ok
  check validate_locale "sr_RS@latin"       ok
  check validate_locale "en"                ok
  check validate_locale "bad locale"        fail
  check validate_locale "en_US;id"          fail
  # Timezones — IANA, multi-segment, underscore allowed
  check validate_timezone_name "Europe/London"                    ok
  check validate_timezone_name "Asia/Kolkata"                     ok
  check validate_timezone_name "America/Argentina/Buenos_Aires"   ok
  check validate_timezone_name "America/Indiana/Indianapolis"     ok
  check validate_timezone_name "Etc/GMT+12"                       ok
  check validate_timezone_name "UTC"                              ok
  check validate_timezone_name "../etc/passwd"                    fail
  check validate_timezone_name "Europe/London;id"                 fail
  check validate_timezone_name "/absolute/path"                   fail
  # https URLs — scheme + no injection / creds
  check validate_https_url "https://example.com"                  ok
  check validate_https_url "https://github.com/u/repo.keys"       ok
  check validate_https_url "http://x.com"                         fail
  check validate_https_url "javascript:alert(1)"                  fail
  check validate_https_url "file:///etc/passwd"                   fail
  check validate_https_url "https://user:pass@x.com"              fail
  # GitHub handles
  check validate_github_handle "torvalds"     ok
  check validate_github_handle "aj-kriel"     ok
  check validate_github_handle "-bad"         fail
  check validate_github_handle "bad-"         fail
  check validate_github_handle "with_under"   fail
  check validate_github_handle ""             fail
  # Task IDs
  check validate_task_id "fstab"              ok
  check validate_task_id "usb_uas_quirks"     ok
  check validate_task_id "Bad-Id"             fail
  check validate_task_id "9fstab"             fail
  check validate_task_id "../escape"          fail
  # Proxy backend URLs
  check validate_proxy_backend_url "https://app:3000"             ok
  check validate_proxy_backend_url "http://127.0.0.1:8080/api"    ok
  check validate_proxy_backend_url "http://x.com; id"             fail
  check validate_proxy_backend_url ""                             fail
  exit $rc
' 2>&1) || fail "validator unit tests failed" "$validator_out"
pass "validator unit tests (hostname/locale/tz/url/github/task/proxy)"

step "CLI arg validators reject malformed values at parse time"
# Each of these must exit non-zero AND print its validator error. The
# validator runs before require_root in parse_args, so non-root is fine
# here — we're only checking the CLI surface.
for pair in \
  "--hostname 'bad host':invalid value" \
  "--timezone '../etc/passwd':invalid value" \
  "--timezone 'Europe/London;id':invalid value" \
  "--locale 'bad locale':invalid value" \
  "--zram-algo unknown:Unsupported" \
  "--ssh-import-github '-bad':invalid GitHub handle" \
  "--ssh-import-url 'http://x.com':URL must begin with https" \
  "--temp-limit 999:in 40..85" \
  "--initial-turbo 120:in 0..60" \
  "--proxy-backend 'http://x.com; id':invalid URL"; do
  args=${pair%:*}
  needle=${pair##*:}
  # shellcheck disable=SC2086  # intentional word-splitting for multi-arg pairs
  out=$(eval "$BIN $args --yes" 2>&1 || true)
  if [[ "$out" != *"$needle"* ]]; then
    fail "CLI validator did not reject '$args' (expected substring: '$needle')" "$out"
  fi
done
pass "CLI arg validators reject malformed input"

step "CLI arg validators accept legitimate edge-case values"
# Regression safety-net for over-tightening. Values here are real IANA
# zones / POSIX locales earlier regex revisions have mis-rejected.
for args in \
  "--timezone America/Argentina/Buenos_Aires" \
  "--timezone Asia/Kolkata" \
  "--timezone UTC" \
  "--locale sr_RS@latin" \
  "--locale C.UTF-8" \
  "--hostname pi5" \
  "--ssh-import-github aj-kriel" \
  "--ssh-import-url https://example.com/k.txt" \
  "--proxy-backend https://app.local:3000/api" \
  "--temp-limit 80" \
  "--initial-turbo 30"; do
  # shellcheck disable=SC2086
  out=$(eval "$BIN $args --list-tasks" 2>&1 || true)
  if [[ "$out" == *"invalid"* || "$out" == *"Unsupported"* ]]; then
    fail "CLI validator wrongly rejected '$args'" "$out"
  fi
done
pass "CLI arg validators accept legitimate edge-case values"

step "error-path: --install-tailscale + --install-wireguard without --allow-both-vpn is mutex"
# Guards the 9.1.2 behaviour that two VPNs without the override
# should hard-error at parse time.
if "$BIN" --install-tailscale --install-wireguard --dry-run --yes 2>/dev/null; then
  fail "expected Tailscale+WireGuard mutex to exit non-zero"
fi
# And the override should pass.
"$BIN" --install-tailscale --install-wireguard --allow-both-vpn --dry-run --yes --list-tasks >/dev/null
pass "error-path: VPN mutex enforced; --allow-both-vpn releases it"

step "error-path: --overclock-conservative + --underclock is mutex"
if "$BIN" --overclock-conservative --underclock --dry-run --yes 2>/dev/null; then
  fail "expected overclock+underclock mutex to exit non-zero"
fi
pass "error-path: clock mutex enforced"

step "config.txt section-aware editing: pi5 entries land in [pi5], not inside a trailing [none]"
# Round-3 regression guard. A user config.txt ending in [none] would
# otherwise silently swallow any Pi-5 dtparam we blindly appended.
# We drive the helper directly (not via the CLI) because the task
# runner gates the full run on is_pi5, which our container stubs
# don't satisfy. Directly exercising lib/util/config_txt.sh proves
# the section router does what pi5_fan / pcie_gen3 now rely on.
cfg_fixture="$TEST_TMP/config_none_tail.txt"
cat > "$cfg_fixture" <<'CFG'
# pi-optimiser test fixture
arm_boost=1
[pi5]
dtparam=uart0=on
[none]
dtparam=safe_mode_gpio=4
CFG
bash -c '
  set -euo pipefail
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/log.sh 2>/dev/null || {
    log_info(){ :; }; log_warn(){ :; }; log_error(){ :; };
  }
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/python.sh
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/config_txt.sh
  ensure_config_key_value "dtparam=fan_temp0=50000" "'"$cfg_fixture"'" pi5
'
grep -q '^\[pi5\]$' "$cfg_fixture" || fail "[pi5] section missing after edit" "$(cat "$cfg_fixture")"
# The new entry must appear BEFORE [none], otherwise the firmware
# will ignore it at boot.
awk '
  /^\[none\]$/ { after_none=1 }
  /dtparam=fan_temp0=50000/ { if (after_none) exit 2 }
' "$cfg_fixture" \
  || fail "pi5 fan entry landed after [none] (would be ignored by firmware)" "$(cat "$cfg_fixture")"
pass "pi5 entries routed into [pi5] even when file ends in [none]"

step "config.txt section-aware editing: existing arm_boost updates in-place (no dup)"
# Second regression: arm_boost=0 already present in the implicit
# [all] preamble. oc_conservative wants arm_boost gone or set to 1
# (well — oc doesn't touch arm_boost today, but the idempotency
# property is what we need to prove).  We use boot_config's
# arm_boost=1 directly against the helper.
cfg_fixture2="$TEST_TMP/config_armboost_zero.txt"
cat > "$cfg_fixture2" <<'CFG'
# fixture — operator has arm_boost disabled
arm_boost=0
dtparam=audio=on
[pi5]
arm_freq=2800
CFG
bash -c '
  set -euo pipefail
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/log.sh 2>/dev/null || {
    log_info(){ :; }; log_warn(){ :; }; log_error(){ :; };
  }
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/python.sh
  # shellcheck disable=SC1091
  source /opt/pi-optimiser/lib/util/config_txt.sh
  ensure_config_key_value "arm_boost=1" "'"$cfg_fixture2"'" all
  # Second call must be a no-op (rc=1) — idempotency check.
  rc=0
  ensure_config_key_value "arm_boost=1" "'"$cfg_fixture2"'" all || rc=$?
  if [[ $rc -ne 1 ]]; then
    echo "second call rc=$rc (expected 1 unchanged)" >&2
    exit 3
  fi
'
arm_boost_count=$(grep -c '^arm_boost=' "$cfg_fixture2" || true)
[[ "$arm_boost_count" == "1" ]] \
  || fail "arm_boost duplicated: $arm_boost_count lines (expected exactly 1)" "$(cat "$cfg_fixture2")"
grep -q '^arm_boost=1$' "$cfg_fixture2" \
  || fail "arm_boost not updated to 1" "$(cat "$cfg_fixture2")"
# And the [pi5] section's arm_freq=2800 must still be intact.
grep -q '^arm_freq=2800$' "$cfg_fixture2" \
  || fail "[pi5] arm_freq clobbered by [all] edit" "$(cat "$cfg_fixture2")"
pass "arm_boost updated in-place inside [all]; no duplicate; [pi5] untouched"

step "config.txt section-aware editing: no .pi-optimiser.tmp leftovers"
# Atomic-write contract: os.replace consumes the staging file. Any
# surviving .pi-optimiser.tmp in /boot/firmware would mean a crash
# between write+replace, which we must catch.
if compgen -G "/boot/firmware/*.pi-optimiser.tmp" >/dev/null 2>&1 \
   || compgen -G "$TEST_TMP/*.pi-optimiser.tmp" >/dev/null 2>&1; then
  fail "orphan .pi-optimiser.tmp file(s) survived"
fi
pass "no orphan .pi-optimiser.tmp files after edits"

# ======================================================================
# Expanded config.txt section-aware test matrix (Round 4).
#
# The Round-3 block above covers:
#   - section=pi5 insertion before a trailing [none]
#   - in-place update + idempotency rc=1 inside [all]
#   - no .pi-optimiser.tmp leftovers
#
# Cases below exercise the remaining corners from the Round-4 matrix:
# file shapes (no sections / only [all] / both [pi5]+[all] / [pi5]+[none]+[cm4] /
# duplicate [all]), cross-section WARN, empty section creation, CRLF + BOM
# normalisation, atomic-write failure safety, cross-task non-interaction,
# and boundary files (empty, single-line-no-newline).
#
# A shared helper sources the helper libraries with log_warn wired to a
# capture file so tests can assert WARNs are actually emitted. All
# fixtures live under $TEST_TMP so they're cleaned on exit.
# ======================================================================

# Path to the run_python+config_txt driver script used by every subtest
# below. Using a file instead of inline `bash -c` heredocs makes the
# fixture content (CRLF, BOM) unambiguous — the driver reads
# configuration from env vars, no shell-level quoting in the payload.
_cfgtest_driver="$TEST_TMP/cfgtest_driver.sh"
cat > "$_cfgtest_driver" <<'DRV'
#!/usr/bin/env bash
# Driver: sources config_txt.sh with a stub log_warn that appends to
# $CFGTEST_WARN_OUT. Dispatches to ensure_config_key_value or
# ensure_config_line based on $CFGTEST_MODE. Returns the helper's rc
# verbatim so callers can distinguish changed(0)/unchanged(1)/error(2).
set -uo pipefail
# Stub the logger *before* sourcing config_txt.sh so the helper's
# log_warn binds to our capture, not the real one.
log_info() { :; }
log_error() { :; }
log_warn() {
  if [[ -n "${CFGTEST_WARN_OUT:-}" ]]; then
    printf 'WARN %s\n' "$*" >>"$CFGTEST_WARN_OUT"
  fi
}
export -f log_info log_error log_warn
# shellcheck disable=SC1091
source /opt/pi-optimiser/lib/util/python.sh
# shellcheck disable=SC1091
source /opt/pi-optimiser/lib/util/config_txt.sh
mode=${CFGTEST_MODE:-kv}
target=${CFGTEST_TARGET:?target required}
section=${CFGTEST_SECTION:-all}
entry=${CFGTEST_ENTRY:?entry required}
rc=0
case "$mode" in
  kv)   ensure_config_key_value "$entry" "$target" "$section" || rc=$? ;;
  line) ensure_config_line      "$entry" "$target" "$section" || rc=$? ;;
  *) echo "unknown CFGTEST_MODE=$mode" >&2; exit 99 ;;
esac
exit $rc
DRV
chmod +x "$_cfgtest_driver"

# Convenience: run the driver with (mode, target, section, entry),
# capturing WARN output into $CFGTEST_WARN_OUT. Echoes the helper rc.
_cfgtest_run() {
  local mode=$1 target=$2 section=$3 entry=$4
  CFGTEST_MODE="$mode" CFGTEST_TARGET="$target" CFGTEST_SECTION="$section" \
    CFGTEST_ENTRY="$entry" CFGTEST_WARN_OUT="${CFGTEST_WARN_OUT:-/dev/null}" \
    "$_cfgtest_driver"
}

step "config.txt[case 1]: file with no sections — section=all appends; section=pi5 creates trailing [pi5]"
# Case 1a: all preamble, no sections, section=all. Entry should be
# appended inside the implicit [all] preamble (no header written).
fx="$TEST_TMP/c1a_nosections.txt"
printf 'arm_boost=1\ndtparam=audio=on\n' >"$fx"
_cfgtest_run kv "$fx" all "gpu_mem=16" >/dev/null
grep -q '^gpu_mem=16$' "$fx" || fail "case 1a: gpu_mem missing" "$(cat "$fx")"
if grep -q '^\[all\]$' "$fx"; then
  fail "case 1a: implicit preamble should NOT sprout an [all] header" "$(cat "$fx")"
fi
# Case 1b: same starting file, section=pi5 → creates trailing [pi5]
# (no [none] tail to insert before, so it goes at EOF).
fx="$TEST_TMP/c1b_nosections_pi5.txt"
printf 'arm_boost=1\ndtparam=audio=on\n' >"$fx"
_cfgtest_run kv "$fx" pi5 "arm_freq=2600" >/dev/null
grep -q '^\[pi5\]$' "$fx" || fail "case 1b: [pi5] header not created" "$(cat "$fx")"
# [pi5] must appear AFTER the preamble lines so the preamble remains
# implicit-[all].
awk '
  /^arm_boost=1$/     { saw_all=1 }
  /^\[pi5\]$/         { if (!saw_all) exit 2; saw_pi5=1 }
  /^arm_freq=2600$/   { if (!saw_pi5) exit 3 }
' "$fx" || fail "case 1b: [pi5] placement wrong" "$(cat "$fx")"
pass "case 1: no-section file — all appends to preamble; pi5 creates trailing [pi5]"

step "config.txt[case 2]: only [all] section present — section=pi5 creates trailing [pi5]"
# Our parser treats the preamble as implicit [all]; an *explicit*
# `[all]` header in the middle of the file becomes a SECOND [all]
# section. We want to verify the section-create path handles that.
fx="$TEST_TMP/c2_only_all.txt"
printf '[all]\narm_boost=1\n' >"$fx"
_cfgtest_run kv "$fx" pi5 "arm_freq=2500" >/dev/null
grep -q '^\[pi5\]$' "$fx" || fail "case 2: [pi5] not created" "$(cat "$fx")"
grep -q '^arm_freq=2500$' "$fx" || fail "case 2: arm_freq not written" "$(cat "$fx")"
pass "case 2: only-[all] file — pi5 section created at EOF"

step "config.txt[case 3]: [pi5]+[all] sections — edits land in the named section"
fx="$TEST_TMP/c3_pi5_and_all.txt"
cat > "$fx" <<'CFG'
arm_boost=1
[pi5]
dtparam=uart0=on
[all]
dtparam=audio=on
CFG
# section=pi5 → edit inside [pi5] body
_cfgtest_run kv "$fx" pi5 "arm_freq=2400" >/dev/null
# section=all → edit inside the first [all] (implicit preamble)
_cfgtest_run kv "$fx" all "gpu_mem=64" >/dev/null
# Preamble-[all] owns 'gpu_mem=64'; [pi5] body owns arm_freq=2400.
awk '
  /^\[pi5\]$/        { in_pi5=1; in_all=0; next }
  /^\[all\]$/        { in_all=1; in_pi5=0; next }
  /^\[/              { in_pi5=0; in_all=0; next }
  /^arm_freq=2400$/  { if (!in_pi5) exit 2 }
  /^gpu_mem=64$/     { if (in_pi5 || in_all) exit 3 }
' "$fx" || fail "case 3: entries landed in wrong sections" "$(cat "$fx")"
pass "case 3: [pi5]+[all] — edits routed to their named sections"

step "config.txt[case 4]: file ending in [none] — section=all inserts before [none]"
# Variant of Round-3's pi5 test, but for section=all. The helper's
# existing logic only inserts BEFORE trailing [none] when CREATING a
# new section; for an existing [all] preamble the preamble already
# precedes [none], so insertion there is automatic. We verify the
# behavioural guarantee from the doc: "section=all → insert before
# [none]".
fx="$TEST_TMP/c4_none_tail.txt"
cat > "$fx" <<'CFG'
arm_boost=1
[none]
dtparam=safe_mode_gpio=4
CFG
_cfgtest_run kv "$fx" all "gpu_mem=16" >/dev/null
awk '
  /^\[none\]$/   { after=1 }
  /^gpu_mem=16$/ { if (after) exit 2 }
' "$fx" || fail "case 4: gpu_mem landed after [none]" "$(cat "$fx")"
pass "case 4: [none]-tailed file — section=all inserts before [none]"

step "config.txt[case 5]: [pi5]+[none]+[cm4] at end — section=pi5 appends inside [pi5]"
# A user file that interleaves [none] doesn't guarantee [cm4] is the
# last terminal. What matters is that a pi5 entry goes inside the
# existing [pi5] body, not inside [cm4] and not as a new [pi5] at EOF.
fx="$TEST_TMP/c5_pi5_none_cm4.txt"
cat > "$fx" <<'CFG'
arm_boost=1
[pi5]
dtparam=uart0=on
[none]
dtparam=safe_mode_gpio=4
[cm4]
dtparam=nvme
CFG
_cfgtest_run kv "$fx" pi5 "arm_freq=2400" >/dev/null
awk '
  /^\[pi5\]$/   { in_pi5=1; next }
  /^\[/         { in_pi5=0; next }
  /^arm_freq=2400$/ { if (!in_pi5) exit 2 }
' "$fx" || fail "case 5: arm_freq not inside [pi5] body" "$(cat "$fx")"
# And [pi5] must NOT have been duplicated.
pi5_count=$(grep -c '^\[pi5\]$' "$fx" || true)
[[ "$pi5_count" == "1" ]] || fail "case 5: [pi5] duplicated ($pi5_count)" "$(cat "$fx")"
pass "case 5: [pi5]+[none]+[cm4] — pi5 edit stays in the [pi5] body"

step "config.txt[case 6]: duplicate [all] sections — first match wins, documented"
# Duplicate [all] sections are operator error (Pi firmware reads them
# all), but the helper must behave *consistently* so a re-run doesn't
# flip between copies. The parser's first-match order means the first
# [all] wins; we codify that here so a future refactor doesn't change
# the tie-breaker silently.
fx="$TEST_TMP/c6_dup_all.txt"
cat > "$fx" <<'CFG'
arm_boost=1
[pi5]
dtparam=uart0=on
[all]
dtparam=audio=on
[all]
dtparam=spi=on
CFG
_cfgtest_run kv "$fx" all "gpu_mem=16" >/dev/null
# The first [all] section is the implicit preamble (index 0), which
# has `arm_boost=1`. The new key must be added to *that* section (the
# preamble, before the [pi5] header), not to the later [all] blocks.
awk '
  /^\[pi5\]$/    { after_pi5=1 }
  /^gpu_mem=16$/ { if (after_pi5) exit 2 }
' "$fx" || fail "case 6: gpu_mem should land in preamble-[all], not later [all]" "$(cat "$fx")"
# And run it again — the helper must be idempotent.
rc=0
_cfgtest_run kv "$fx" all "gpu_mem=16" >/dev/null || rc=$?
[[ "$rc" == "1" ]] || fail "case 6: second run rc=$rc (expected 1 unchanged)"
dup=$(grep -c '^gpu_mem=16$' "$fx" || true)
[[ "$dup" == "1" ]] || fail "case 6: gpu_mem duplicated on re-run: $dup" "$(cat "$fx")"
pass "case 6: duplicate [all] — first (preamble) wins, idempotent"

step "config.txt[case 7]: empty section body — new key is first entry inside [pi5]"
fx="$TEST_TMP/c7_empty_section.txt"
cat > "$fx" <<'CFG'
arm_boost=1
[pi5]
CFG
_cfgtest_run kv "$fx" pi5 "arm_freq=2600" >/dev/null
awk '
  /^\[pi5\]$/       { in_pi5=1; next }
  /^\[/             { in_pi5=0; next }
  /^arm_freq=2600$/ { if (!in_pi5) exit 2 }
' "$fx" || fail "case 7: arm_freq not placed in empty [pi5]" "$(cat "$fx")"
pass "case 7: entry into previously-empty [pi5] body"

step "config.txt[case 9]: cross-section conflict emits WARN sidecar"
# Key already present in [all]; caller requests [pi5]. Documented
# behaviour: add to [pi5], leave [all] intact, emit a WARN.
fx="$TEST_TMP/c9_cross_section.txt"
cat > "$fx" <<'CFG'
arm_boost=1
[pi5]
dtparam=uart0=on
CFG
warn_log="$TEST_TMP/c9_warns.log"
: > "$warn_log"
CFGTEST_WARN_OUT="$warn_log" _cfgtest_run kv "$fx" pi5 "arm_boost=1" >/dev/null
# [all] copy must still be there
grep -q '^arm_boost=1$' "$fx" || fail "case 9: [all] arm_boost was removed" "$(cat "$fx")"
# And a second arm_boost=1 must be inside [pi5]
awk '
  /^\[pi5\]$/      { in_pi5=1; next }
  /^\[/            { in_pi5=0; next }
  /^arm_boost=1$/  { if (in_pi5) hit=1 }
  END { exit (hit ? 0 : 2) }
' "$fx" || fail "case 9: arm_boost not duplicated into [pi5]" "$(cat "$fx")"
# WARN sidecar must contain a cross-section message
grep -qi 'already set in \[all\]' "$warn_log" \
  || fail "case 9: WARN about cross-section not emitted" "$(cat "$warn_log")"
pass "case 9: cross-section conflict writes to requested section + emits WARN"

step "config.txt[case 10]: ensure_config_line treats '#key=1' as matching 'key=1'"
# There is no dedicated comment-out helper. But ensure_config_line's
# line-match strips leading '#' so a pre-commented line is recognised.
# That's the documented behaviour; any change needs a deliberate test
# rewrite rather than silent drift.
fx="$TEST_TMP/c10_commented.txt"
printf '# fixture\n#arm_boost=1\n' >"$fx"
rc=0
_cfgtest_run line "$fx" all "arm_boost=1" >/dev/null || rc=$?
# Helper should have normalised the commented form to the live form
# (changed rc=0). There must be exactly ONE active arm_boost=1 line
# and no leftover #arm_boost=1.
[[ "$rc" == "0" ]] || fail "case 10: helper rc=$rc (expected 0 changed)"
grep -q '^arm_boost=1$' "$fx" \
  || fail "case 10: commented line was not promoted to active" "$(cat "$fx")"
if grep -q '^#arm_boost=1$' "$fx"; then
  fail "case 10: commented duplicate survived" "$(cat "$fx")"
fi
pass "case 10: ensure_config_line promotes a pre-commented match in-place"

step "config.txt[case 12]: kv=pi5 then kv=all — both present, WARN on second"
fx="$TEST_TMP/c12_both_sections.txt"
printf 'dtparam=audio=on\n' >"$fx"
warn_log="$TEST_TMP/c12_warns.log"
: > "$warn_log"
_cfgtest_run kv "$fx" pi5 "arm_boost=1" >/dev/null
CFGTEST_WARN_OUT="$warn_log" _cfgtest_run kv "$fx" all "arm_boost=1" >/dev/null
# Expect exactly two arm_boost=1 lines: one in preamble-all, one in [pi5].
total=$(grep -c '^arm_boost=1$' "$fx" || true)
[[ "$total" == "2" ]] || fail "case 12: expected 2 arm_boost lines, got $total" "$(cat "$fx")"
# The [all]-side call must emit a WARN because [pi5] already has it.
grep -qi 'already set in \[pi5\]' "$warn_log" \
  || fail "case 12: WARN about [pi5] conflict not emitted" "$(cat "$warn_log")"
pass "case 12: kv written to [pi5] then [all] — both present + WARN emitted"

step "config.txt[case 13]: update value within same section (pi5 1 → pi5 0)"
fx="$TEST_TMP/c13_update.txt"
printf 'dtparam=audio=on\n' >"$fx"
_cfgtest_run kv "$fx" pi5 "arm_boost=1" >/dev/null
_cfgtest_run kv "$fx" pi5 "arm_boost=0" >/dev/null
grep -q '^arm_boost=0$' "$fx" || fail "case 13: arm_boost not updated to 0" "$(cat "$fx")"
if grep -q '^arm_boost=1$' "$fx"; then
  fail "case 13: old arm_boost=1 still present" "$(cat "$fx")"
fi
total=$(grep -c '^arm_boost=' "$fx" || true)
[[ "$total" == "1" ]] || fail "case 13: expected 1 arm_boost line, got $total" "$(cat "$fx")"
pass "case 13: same-section update replaces value in place"

step "config.txt[case 14]: CRLF input is normalised to LF on write"
fx="$TEST_TMP/c14_crlf.txt"
# Build a CRLF file deliberately with printf; don't rely on editor.
printf '# crlf fixture\r\narm_boost=1\r\n[pi5]\r\ndtparam=uart0=on\r\n' >"$fx"
_cfgtest_run kv "$fx" pi5 "arm_freq=2400" >/dev/null
# After the rewrite, the file must contain NO CR bytes.
if grep -lU $'\r' "$fx" >/dev/null 2>&1; then
  fail "case 14: CRLF survived rewrite" "$(od -c "$fx" | head -5)"
fi
# And the new entry must still be in [pi5].
grep -q '^arm_freq=2400$' "$fx" || fail "case 14: arm_freq missing" "$(cat "$fx")"
pass "case 14: CRLF input rewritten as LF-only"

step "config.txt[case 15]: BOM at file start is handled"
fx="$TEST_TMP/c15_bom.txt"
# UTF-8 BOM (EF BB BF) followed by normal content.
printf '\xef\xbb\xbfarm_boost=1\ndtparam=audio=on\n' >"$fx"
rc=0
_cfgtest_run kv "$fx" pi5 "arm_freq=2400" >/dev/null || rc=$?
# Helper must not have crashed.
[[ "$rc" == "0" ]] || fail "case 15: helper rc=$rc on BOM input"
# The rest of the operator's content must still be readable.
grep -q '^dtparam=audio=on$' "$fx" || fail "case 15: preamble content lost" "$(cat "$fx")"
grep -q '^\[pi5\]$' "$fx" || fail "case 15: [pi5] missing" "$(cat "$fx")"
grep -q '^arm_freq=2400$' "$fx" || fail "case 15: new entry missing" "$(cat "$fx")"
pass "case 15: BOM input preserved/tolerated; rest of file intact"

step "config.txt[case 16]: atomic write — blocked staging path leaves original unchanged"
# We run as root in the test container, which bypasses normal directory
# permissions (CAP_DAC_OVERRIDE). Instead of a read-only dir, we block
# the staging path itself: pre-create the `.pi-optimiser.tmp` sibling
# as a *directory* so Python's `open(tmp_path, 'w')` raises
# IsADirectoryError. The helper must return non-zero (rc=2) and leave
# the original file byte-for-byte unchanged.
c16_dir="$TEST_TMP/c16_blocked"
mkdir -p "$c16_dir"
fx="$c16_dir/config.txt"
printf 'arm_boost=1\ndtparam=audio=on\n' >"$fx"
pre_sha=$(sha256sum "$fx" | awk '{print $1}')
# Block the staging path as documented in ensure_config_key_value:
#   tmp_path = config_path.with_suffix(config_path.suffix + '.pi-optimiser.tmp')
# For config.txt that's config.txt.pi-optimiser.tmp.
mkdir "$c16_dir/config.txt.pi-optimiser.tmp"
touch "$c16_dir/config.txt.pi-optimiser.tmp/.keep"
rc=0
_cfgtest_run kv "$fx" pi5 "arm_freq=2400" >/dev/null 2>&1 || rc=$?
post_sha=$(sha256sum "$fx" | awk '{print $1}')
[[ "$rc" == "2" ]] \
  || fail "case 16: helper rc=$rc on blocked staging path (expected 2)"
[[ "$pre_sha" == "$post_sha" ]] \
  || fail "case 16: original file changed despite failed write (pre=$pre_sha post=$post_sha)" "$(cat "$fx")"
# Clean up the blocking dir so the post-matrix tmp-leftover check
# doesn't misinterpret it.
rm -rf "$c16_dir/config.txt.pi-optimiser.tmp"
pass "case 16: failed atomic write leaves original file unchanged (rc=2)"

step "config.txt[case 18]: cross-task non-interaction — edits to [all] and [pi5] compose"
fx="$TEST_TMP/c18_compose.txt"
printf 'dtparam=audio=on\n' >"$fx"
# "Task A" edits [all].
_cfgtest_run kv "$fx" all "gpu_mem=16" >/dev/null
# "Task B" edits [pi5].
_cfgtest_run kv "$fx" pi5 "arm_freq=2400" >/dev/null
# Both entries must be present in their own sections, original
# dtparam=audio=on still intact.
grep -q '^dtparam=audio=on$' "$fx" || fail "case 18: pre-existing audio=on lost"
grep -q '^gpu_mem=16$' "$fx" || fail "case 18: [all] edit missing"
grep -q '^arm_freq=2400$' "$fx" || fail "case 18: [pi5] edit missing"
awk '
  /^\[pi5\]$/       { in_pi5=1; next }
  /^\[/             { in_pi5=0; next }
  /^gpu_mem=16$/    { if (in_pi5) exit 2 }
  /^arm_freq=2400$/ { if (!in_pi5) exit 3 }
' "$fx" || fail "case 18: edits landed in wrong sections" "$(cat "$fx")"
pass "case 18: Task A ([all]) + Task B ([pi5]) compose without interaction"

step "config.txt[case 19]: empty file — section=all adds a single-key file"
fx="$TEST_TMP/c19_empty.txt"
: > "$fx"
_cfgtest_run kv "$fx" all "arm_boost=1" >/dev/null
[[ "$(wc -l <"$fx")" == "1" ]] \
  || fail "case 19: expected 1-line file, got $(wc -l <"$fx")" "$(cat "$fx")"
grep -q '^arm_boost=1$' "$fx" || fail "case 19: content wrong" "$(cat "$fx")"
pass "case 19: empty file gains exactly one key=value line"

step "config.txt[case 20]: single-line no trailing newline — appended content keeps LF separator"
fx="$TEST_TMP/c20_no_newline.txt"
printf 'arm_boost=1' >"$fx"  # deliberately no \n
# Confirm the fixture really has no trailing newline. Use od so we
# don't depend on xxd (not in the trixie-slim image).
last_byte() { od -An -tx1 -N1 -j"$(($(wc -c <"$1")-1))" "$1" | tr -d ' \n'; }
[[ "$(last_byte "$fx")" != "0a" ]] \
  || fail "case 20: fixture unexpectedly had trailing newline"
_cfgtest_run kv "$fx" all "gpu_mem=16" >/dev/null
# After the rewrite, lines must be properly separated.
grep -q '^arm_boost=1$' "$fx" || fail "case 20: original line broken" "$(cat "$fx")"
grep -q '^gpu_mem=16$' "$fx" || fail "case 20: appended line missing" "$(cat "$fx")"
# And the file must end with a newline now (payload = '\n'.join + '\n').
[[ "$(last_byte "$fx")" == "0a" ]] \
  || fail "case 20: output missing trailing newline" "$(od -c "$fx" | tail -2)"
pass "case 20: single-line-no-newline fixture gains a proper LF separator"

step "config.txt expanded-matrix: no .pi-optimiser.tmp leftovers after full matrix run"
# Check the whole test tree recursively — fixtures under $TEST_TMP
# live in per-case subdirectories, so a bare glob isn't enough.
shopt -s globstar nullglob
leftovers=( "$TEST_TMP"/**/*.pi-optimiser.tmp "$TEST_TMP"/*.pi-optimiser.tmp )
shopt -u globstar nullglob
if (( ${#leftovers[@]} > 0 )); then
  fail "stray .pi-optimiser.tmp after expanded matrix: ${leftovers[*]}"
fi
pass "no stray staging files after expanded matrix"

echo "[undo-integration]"
step "[undo-integration] end-to-end rollback of edit + create records"
# Drive pi_undo_task directly against a hand-crafted journal so we can
# cover the full Round-3 matrix (old-style edits, new-style edits,
# create records, missing backups, path-traversal rejection, dry-run
# preview, idempotency) without needing root or the task-loop machinery.
# The journal JSON schema is frozen by lib/util/backup.sh::_backup_journal_flush
# so the fixture below matches what the hot path actually produces.
UNDO_ROOT=$(mktemp -d /tmp/pi-optimiser-undo.XXXXXX)
# Extend the cleanup trap so a mid-step failure doesn't leak fixtures.
trap 'rm -rf "$TEST_TMP" "$UNDO_ROOT"' EXIT
mkdir -p "$UNDO_ROOT/etc/pi-optimiser/backups" \
         "$UNDO_ROOT/etc/target" \
         "$UNDO_ROOT/etc/systemd/system" \
         "$UNDO_ROOT/etc/systemd/journald.conf.d"

# --- Fixture files --------------------------------------------------
# (edit 1) Pre-Round-3 compat: record carries ONLY original + backup —
# no kind/mode/uid/gid. undo.sh must still restore it.
edit_old="$UNDO_ROOT/etc/target/old-style.conf"
edit_old_bak="${edit_old}.pi-optimiser.20240101000000"
printf 'pristine-old\n' > "$edit_old_bak"
printf 'task-mutated-old\n' > "$edit_old"

# (edit 2) Round-3 full-metadata record.
edit_new="$UNDO_ROOT/etc/target/new-style.conf"
edit_new_bak="${edit_new}.pi-optimiser.20240101000000"
printf 'pristine-new\n' > "$edit_new_bak"
chmod 0644 "$edit_new_bak"
printf 'task-mutated-new\n' > "$edit_new"
chmod 0600 "$edit_new"
new_mode=420  # 0644 as int — matches what backup.sh records
new_uid=$(id -u)
new_gid=$(id -g)

# (create) New systemd unit file created by the task — exercises the
# REMOVED -> disable + daemon-reload branch of the shell post-processor.
create_unit="$UNDO_ROOT/etc/systemd/system/pi-undo-test.service"
printf '[Unit]\nDescription=pi-undo-test\n' > "$create_unit"

# (create, drop-in) File under /etc/systemd/*.d — also triggers
# daemon-reload but should NOT invoke systemctl disable.
create_dropin="$UNDO_ROOT/etc/systemd/journald.conf.d/99-pi-undo-test.conf"
printf '[Journal]\nStorage=volatile\n' > "$create_dropin"

# (edit, missing backup) Operator cleaned up the backup file. undo
# must fail loudly with MISSING — not silently succeed.
edit_missing="$UNDO_ROOT/etc/target/missing-backup.conf"
edit_missing_bak="${edit_missing}.pi-optimiser.20240101000000"
printf 'content\n' > "$edit_missing"
# Deliberately NOT creating $edit_missing_bak.

# --- Build the journal ---------------------------------------------
journal="$UNDO_ROOT/etc/pi-optimiser/backups/undo_integration.json"
python3 - "$journal" \
  "$edit_old" "$edit_old_bak" \
  "$edit_new" "$edit_new_bak" "$new_mode" "$new_uid" "$new_gid" \
  "$create_unit" "$create_dropin" \
  "$edit_missing" "$edit_missing_bak" <<'PY'
import json, sys
(journal,
 eo, eo_bak,
 en, en_bak, en_mode, en_uid, en_gid,
 cu, cd,
 em, em_bak) = sys.argv[1:]
data = {
    "runs": [{
        "run_id": "undo-integration-run",
        "task": "undo_integration",
        "files": [
            # Old-journal compat: bare original + backup.
            {"original": eo, "backup": eo_bak},
            # New-style edit with full metadata.
            {
                "original": en, "backup": en_bak,
                "mode": int(en_mode), "uid": int(en_uid),
                "gid": int(en_gid), "is_symlink": False,
            },
            # Create records.
            {"original": cu, "created": True},
            {"original": cd, "created": True},
            # Missing-backup edit.
            {"original": em, "backup": em_bak},
            # Path-traversal bait — must be rejected.
            {"original": "/../etc/passwd", "backup": em_bak},
        ],
    }]
}
with open(journal, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
PY

# Helper: source undo.sh in a subshell with state/systemctl stubbed out.
# We define log_{info,warn,error} as plain printf shims AFTER sourcing
# log.sh, so we don't depend on LOG_FILE / run_python init semantics
# the real CLI sets up. run_python is the only helper we actually need
# from the util tree because pi_undo_task's Python block is fed through
# it. PI_OUTPUT_JSON=0 keeps log.sh's internal stderr routing sane even
# though we override its log_* functions.
run_undo() {
  local dry=${1:-0}
  UNDO_ROOT="$UNDO_ROOT" DRY_RUN="$dry" bash -c '
    set -uo pipefail
    MARKER_DIR="$UNDO_ROOT/etc/pi-optimiser"
    export MARKER_DIR DRY_RUN
    PI_NON_INTERACTIVE=1
    PI_OUTPUT_JSON=0
    # shellcheck disable=SC1091
    source /opt/pi-optimiser/lib/util/python.sh
    # Stub the log helpers — we do NOT source log.sh because it requires
    # LOG_FILE and CURRENT_TASK to be set via init_logging, neither of
    # which make sense in a fixture-only unit test.
    log_info(){  printf "INFO %s\n" "$*"; }
    log_warn(){  printf "WARN %s\n" "$*" >&2; }
    log_error(){ printf "ERROR %s\n" "$*" >&2; }
    # shellcheck disable=SC1091
    source /opt/pi-optimiser/lib/util/validate.sh
    clear_task_state(){ :; }
    is_task_done(){ return 1; }
    systemctl(){ :; }
    # shellcheck disable=SC1091
    source /opt/pi-optimiser/lib/features/undo.sh
    pi_undo_task undo_integration
  '
}

# --- Scenario: dry-run preview shows all expected lines -----------
dry_out=$(run_undo 1 2>&1 || true)
[[ "$dry_out" == *"rm $create_unit"* ]] \
  || fail "dry-run missing 'rm $create_unit'" "$dry_out"
[[ "$dry_out" == *"rm $create_dropin"* ]] \
  || fail "dry-run missing 'rm $create_dropin'" "$dry_out"
[[ "$dry_out" == *"$edit_old <- $edit_old_bak"* ]] \
  || fail "dry-run missing edit restore line" "$dry_out"
# Nothing should have been modified in dry-run.
[[ "$(cat "$edit_old")" == "task-mutated-old" ]] \
  || fail "dry-run mutated $edit_old"
[[ -f "$create_unit" ]] || fail "dry-run removed $create_unit"
pass "[undo-integration] dry-run preview covers edit + create, no side effects"

# --- Scenario: real run restores + removes, and fails on MISSING ---
# Fixture includes a deliberately missing backup AND an unsafe path,
# so pi_undo_task MUST exit non-zero. That is the Round-4 bugfix —
# prior behaviour let MISSING / REJECT silently sail through with rc=0.
real_out=$(run_undo 0 2>&1 || true)
[[ "$(cat "$edit_old")" == "pristine-old" ]] \
  || fail "old-style edit not restored" "$real_out"
[[ "$(cat "$edit_new")" == "pristine-new" ]] \
  || fail "new-style edit not restored" "$real_out"
actual_mode=$(stat -c "%a" "$edit_new")
[[ "$actual_mode" == "644" ]] \
  || fail "new-style edit mode not restored (got $actual_mode, want 644)" "$real_out"
[[ ! -e "$create_unit" ]] \
  || fail "create-unit file not removed" "$real_out"
[[ ! -e "$create_dropin" ]] \
  || fail "create-dropin drop-in not removed" "$real_out"
[[ "$real_out" == *"MISSING"* ]] \
  || fail "MISSING line absent from real undo output" "$real_out"
[[ "$real_out" == *"REJECT"* ]] \
  || fail "path-traversal REJECT line absent from undo output" "$real_out"
# Shell must have converted MISSING/REJECT into a non-zero exit.
if run_undo 0 >/dev/null 2>&1; then
  fail "pi_undo_task exited 0 despite MISSING + REJECT entries" "$real_out"
fi
pass "[undo-integration] edits restored, creates removed, MISSING+REJECT fail loudly"

# --- Scenario: idempotency — second run is a safe replay ---------
# Rebuild a journal that only references the now-GONE create records +
# the already-restored edits (no missing backup, no traversal). Run
# undo TWICE back-to-back; second run should be a harmless replay.
journal2="$UNDO_ROOT/etc/pi-optimiser/backups/undo_idempotent.json"
python3 - "$journal2" \
  "$edit_old" "$edit_old_bak" \
  "$edit_new" "$edit_new_bak" "$new_mode" "$new_uid" "$new_gid" \
  "$create_unit" "$create_dropin" <<'PY'
import json, sys
(journal,
 eo, eo_bak,
 en, en_bak, en_mode, en_uid, en_gid,
 cu, cd) = sys.argv[1:]
data = {"runs": [{
    "run_id": "idempotent",
    "task": "undo_idempotent",
    "files": [
        {"original": eo, "backup": eo_bak},
        {"original": en, "backup": en_bak,
         "mode": int(en_mode), "uid": int(en_uid),
         "gid": int(en_gid), "is_symlink": False},
        {"original": cu, "created": True},
        {"original": cd, "created": True},
    ],
}]}
with open(journal, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
PY
idem_out=$(UNDO_ROOT="$UNDO_ROOT" bash -c '
  set -uo pipefail
  MARKER_DIR="$UNDO_ROOT/etc/pi-optimiser"
  export MARKER_DIR
  DRY_RUN=0
  PI_NON_INTERACTIVE=1
  PI_OUTPUT_JSON=0
  source /opt/pi-optimiser/lib/util/python.sh
  log_info(){  printf "INFO %s\n" "$*"; }
  log_warn(){  printf "WARN %s\n" "$*" >&2; }
  log_error(){ printf "ERROR %s\n" "$*" >&2; }
  source /opt/pi-optimiser/lib/util/validate.sh
  clear_task_state(){ :; }
  is_task_done(){ return 1; }
  systemctl(){ :; }
  source /opt/pi-optimiser/lib/features/undo.sh
  pi_undo_task undo_idempotent
  echo ---SECOND-RUN---
  pi_undo_task undo_idempotent
' 2>&1) || fail "idempotent undo exited non-zero" "$idem_out"
# The second run must produce GONE lines for already-removed create files.
gone_count=$(printf '%s\n' "$idem_out" | grep -c $'^GONE\t' || true)
(( gone_count >= 2 )) \
  || fail "idempotent second run didn't GONE the removed files (got $gone_count)" "$idem_out"
pass "[undo-integration] idempotent: second --undo is a harmless replay"

step "bundle: build + bash -n + --version"
scripts/build-bundle.sh "$TEST_TMP/bundle.sh"
bash -n "$TEST_TMP/bundle.sh"
"$TEST_TMP/bundle.sh" --version >/dev/null
bundle_task_lines=$("$TEST_TMP/bundle.sh" --list-tasks | wc -l)
(( bundle_task_lines > 0 )) || fail "bundle --list-tasks emitted nothing"
# Bundle must also know about the 9.3 flags (regression catcher
# for scripts/build-bundle.sh silently dropping a lib/tasks file).
bundle_help=$("$TEST_TMP/bundle.sh" --help)
for flag in --install-hailo --install-chrony --headless-gpu-mem \
            --usb-uas-quirks --disable-ipv6 --install-firewall \
            --power-off-halt --quiet-boot --disable-leds; do
  [[ "$bundle_help" == *"$flag"* ]] \
    || fail "bundle --help missing $flag (build-bundle dropped a task file?)" "$bundle_help"
done
pass "bundle (9.3 flags present)"

printf '\nAll integration checks passed.\n'
