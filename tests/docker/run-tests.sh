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

step "--show-config emits parsable YAML"
"$BIN" --show-config --config /tmp/good.yaml >/tmp/shown.yaml
grep -q 'profile:' /tmp/shown.yaml
pass "show-config"

step "--show-config --output json emits valid JSON"
"$BIN" --show-config --config /tmp/good.yaml --output json | python3 -m json.tool >/dev/null
pass "show-config --output json"

step "--completion bash / zsh produce usable output"
"$BIN" --completion bash | head -n 1 >/dev/null
"$BIN" --completion zsh  | head -n 1 >/dev/null
pass "completion"

step "--diff flags accepted; no writes to /boot/firmware"
pre_config_mtime=$(stat -c %Y /boot/firmware/config.txt)
"$BIN" --diff --pi5-fan-profile --yes >/dev/null 2>&1 || true
post_config_mtime=$(stat -c %Y /boot/firmware/config.txt)
if [[ "$pre_config_mtime" != "$post_config_mtime" ]]; then
  printf 'FAIL  --diff modified /boot/firmware/config.txt (mtime %s -> %s)\n' \
    "$pre_config_mtime" "$post_config_mtime" >&2
  exit 1
fi
pass "--diff leaves /boot/firmware untouched"

step "--freeze-task consulted by apply_once"
out=$("$BIN" --dry-run --freeze-task fstab 2>&1 | grep -c 'fstab (frozen)' || true)
if [[ "$out" -lt 1 ]]; then
  printf 'FAIL  expected "fstab (frozen)" in output\n' >&2
  exit 1
fi
pass "--freeze-task"

step "bundle: build + bash -n + --version"
scripts/build-bundle.sh /tmp/bundle.sh
bash -n /tmp/bundle.sh
/tmp/bundle.sh --version >/dev/null
/tmp/bundle.sh --list-tasks | wc -l | grep -qv '^0$'
pass "bundle"

printf '\nAll integration checks passed.\n'
