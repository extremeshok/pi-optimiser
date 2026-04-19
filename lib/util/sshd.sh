# ======================================================================
# lib/util/sshd.sh — sshd_config editor
#
# Functions: update_sshd_config_option
# ======================================================================

# Ensure sshd_config directive is set to the specified value.
update_sshd_config_option() {
  local key=$1
  local value=$2
  local file=${3:-/etc/ssh/sshd_config}
  local result=""
  local rc=0
  result=$(SSHD_CONFIG="$file" SSHD_KEY="$key" SSHD_VALUE="$value" run_python <<'PY'
import os
from pathlib import Path

path = Path(os.environ['SSHD_CONFIG'])
key = os.environ['SSHD_KEY']
key_lower = key.lower()
value = os.environ['SSHD_VALUE']

try:
    lines = path.read_text().splitlines()
except FileNotFoundError:
    lines = []

new_lines = []
found = False
changed = False

for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        new_lines.append(line)
        continue
    parts = stripped.split(None, 1)
    directive = parts[0].lower()
    if directive == key_lower:
        if not found:
            expected = f"{key} {value}"
            new_lines.append(expected)
            found = True
            if len(parts) == 1 or parts[1].strip() != value:
                changed = True
        else:
            changed = True
        continue
    new_lines.append(line)

if not found:
    new_lines.append(f"{key} {value}")
    changed = True

output = '\n'.join(new_lines) + '\n'
try:
    current = path.read_text()
except FileNotFoundError:
    current = ''
if current != output:
    path.write_text(output)
    print('changed')
else:
    print('unchanged')
PY
  ) || rc=$?
  if [[ $rc -ne 0 ]]; then
    log_warn "Failed to update ${key} in $file"
    return 1
  fi
  result=${result//$'\n'/}
  if [[ $result == "changed" ]]; then
    log_info "Updated ${key} in $file"
  else
    log_info "${key} already set in $file"
  fi
}
