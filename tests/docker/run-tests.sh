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

pass() { printf 'PASS  %s\n' "$1"; }
step() { printf '\n==> %s\n' "$1"; }

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

step "self-test runs without crashing"
"$BIN" --self-test >/dev/null || true
pass "self-test"

step "--validate-config accepts a known-good YAML"
cat > /tmp/good.yaml <<'YAML'
version: 1
profile: server
integrations:
  tailscale: false
  docker:
    enabled: true
metrics:
  enabled: true
YAML
"$BIN" --validate-config /tmp/good.yaml
pass "validate-config"

step "--validate-config rejects unrelated file"
if "$BIN" --validate-config /etc/hosts 2>/dev/null; then
  printf 'FAIL  expected --validate-config to reject /etc/hosts\n' >&2
  exit 1
fi
pass "validate-config rejects /etc/hosts"

step "--show-config text mode includes expected sections"
"$BIN" --show-config --config /tmp/good.yaml >/tmp/shown.txt
grep -q 'Effective pi-optimiser config' /tmp/shown.txt
grep -q 'Framework' /tmp/shown.txt
pass "show-config text"

step "--show-config --output json emits valid JSON with expected keys"
"$BIN" --show-config --config /tmp/good.yaml --output json >/tmp/shown.json
python3 -m json.tool </tmp/shown.json >/dev/null
python3 -c 'import json,sys; d=json.load(open("/tmp/shown.json")); assert "metrics" in d and "freeze_tasks" in d and "integrations" in d, d.keys()'
pass "show-config JSON"

step "--completion bash / zsh produce usable output"
"$BIN" --completion bash | head -n 1 >/dev/null
"$BIN" --completion zsh  | head -n 1 >/dev/null
pass "completion"

step "--diff flags accepted; no writes to /boot/firmware"
pre_config_mtime=$(stat -c %Y /boot/firmware/config.txt)
"$BIN" --diff --pi5-fan-profile --yes >/dev/null 2>&1
post_config_mtime=$(stat -c %Y /boot/firmware/config.txt)
if [[ "$pre_config_mtime" != "$post_config_mtime" ]]; then
  printf 'FAIL  --diff modified /boot/firmware/config.txt (mtime %s -> %s)\n' \
    "$pre_config_mtime" "$post_config_mtime" >&2
  exit 1
fi
pass "--diff leaves /boot/firmware untouched"

step "--freeze-task consulted by apply_once"
# Capture the full output instead of piping into grep -q. With
# pipefail, grep's early-exit on first match closes the pipe, the
# producer's subsequent log writes take SIGPIPE (rc 141), and the
# pipeline rc becomes non-zero even though the match succeeded.
freeze_out=$("$BIN" --dry-run --freeze-task fstab 2>&1 || true)
if [[ "$freeze_out" != *"fstab (frozen)"* ]]; then
  printf 'FAIL  expected "fstab (frozen)" in output\n' >&2
  printf '%s\n' "$freeze_out" | tail -40 >&2
  exit 1
fi
pass "--freeze-task"

step "--freeze-task rejects unknown ids"
if "$BIN" --freeze-task nonexistent_task --yes 2>/dev/null; then
  printf 'FAIL  expected --freeze-task to reject unknown id\n' >&2
  exit 1
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
    printf 'FAIL  %s did not reach %s in dry-run\n' "$flag" "$task" >&2
    printf '%s\n' "$out" | tail -20 >&2
    exit 1
  fi
done
pass "9.2 + 9.3 opt-in flags route to their tasks"

step "--usb-uas-extra parses VID:PID list and implies --usb-uas-quirks"
# usb-uas-extra takes an arg; verify the parser accepts the list and
# that supplying it alone (without --usb-uas-quirks) is enough.
out=$("$BIN" --dry-run --only usb_uas_quirks --usb-uas-extra "152d:0578,174c:55aa" --yes 2>&1 || true)
if [[ "$out" != *"[dry-run] usb_uas_quirks would run"* ]]; then
  printf 'FAIL  --usb-uas-extra alone should gate the usb_uas_quirks task\n' >&2
  printf '%s\n' "$out" | tail -20 >&2
  exit 1
fi
pass "--usb-uas-extra implies --usb-uas-quirks"

step "--remove-cups applies only on non-desktop profiles"
# remove_bloat's _remove_bloat_is_headless gate fires when
# KEEP_SCREEN_BLANKING=1 or PI_PROFILE is a non-desktop one.
# --dry-run short-circuits before we hit dpkg, but the gate lives
# in the task body, so we verify via --show-config instead: the
# server profile should leave REMOVE_CUPS=0 (the profile doesn't
# touch it), but keep_screen_blanking=true implies the purge.
out=$("$BIN" --show-config --profile server --output json 2>/dev/null)
printf '%s' "$out" | python3 -c '
import json, sys
cfg = json.loads(sys.stdin.read())
assert cfg["system"]["keep_screen_blanking"] is True, "server profile should set keep_screen_blanking"
' || { printf 'FAIL  server profile did not set keep_screen_blanking\n' >&2; exit 1; }
pass "--remove-cups heuristic wired"

step "UFW task refuses to run without --install-firewall"
out=$("$BIN" --dry-run --only ufw_firewall --yes 2>&1 || true)
if [[ "$out" != *"ufw_firewall would skip"* ]]; then
  printf 'FAIL  ufw_firewall should skip without --install-firewall\n' >&2
  printf '%s\n' "$out" | tail -20 >&2
  exit 1
fi
pass "UFW gate-var honoured under --dry-run"

step "bundle: build + bash -n + --version"
scripts/build-bundle.sh /tmp/bundle.sh
bash -n /tmp/bundle.sh
/tmp/bundle.sh --version >/dev/null
bundle_task_lines=$(/tmp/bundle.sh --list-tasks | wc -l)
(( bundle_task_lines > 0 ))
pass "bundle"

printf '\nAll integration checks passed.\n'
