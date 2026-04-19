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

step "bundle: build + bash -n + --version"
scripts/build-bundle.sh /tmp/bundle.sh
bash -n /tmp/bundle.sh
/tmp/bundle.sh --version >/dev/null
bundle_task_lines=$(/tmp/bundle.sh --list-tasks | wc -l)
(( bundle_task_lines > 0 ))
pass "bundle"

printf '\nAll integration checks passed.\n'
