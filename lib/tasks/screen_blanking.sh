# >>> pi-task
# id: screen_blanking
# version: 1.1.0
# description: Disable console and desktop screen blanking
# category: display
# default_enabled: 1
# power_sensitive: 0
# skip_var: KEEP_SCREEN_BLANKING
# <<< pi-task

pi_task_register screen_blanking \
  description="Disable console and desktop screen blanking" \
  category=display \
  version=1.1.0 \
  default_enabled=1 \
  skip_var=KEEP_SCREEN_BLANKING

run_screen_blanking() {
  if [[ ${KEEP_SCREEN_BLANKING:-0} -eq 1 ]]; then
    log_info "Screen blanking preserved by user request"
    pi_skip_reason "screen blanking preserved"
    return 2
  fi
  if command -v raspi-config >/dev/null 2>&1; then
    if raspi-config nonint do_blanking 1 >/dev/null 2>&1; then
      log_info "Disabled screen blanking via raspi-config"
    else
      log_warn "raspi-config could not disable screen blanking"
    fi
  fi

  if [[ -f "$CMDLINE_FILE" ]] && ! grep -qw 'consoleblank=0' "$CMDLINE_FILE"; then
    backup_file "$CMDLINE_FILE"
    CMDLINE_PATH="$CMDLINE_FILE" run_python <<'PY'
import os
from pathlib import Path
path = Path(os.environ['CMDLINE_PATH'])
content = path.read_text().strip()
parts = content.split()
if "consoleblank=0" not in parts:
    parts.append("consoleblank=0")
    path.write_text(" ".join(parts) + "\n")
PY
    log_info "Added consoleblank=0 to cmdline.txt"
  fi

  if [[ -f /etc/kbd/config ]]; then
    backup_file /etc/kbd/config
    if grep -q '^BLANK_TIME=' /etc/kbd/config; then
      sed -i 's/^BLANK_TIME=.*/BLANK_TIME=0/' /etc/kbd/config
    else
      echo 'BLANK_TIME=0' >> /etc/kbd/config
    fi
    if grep -q '^POWERDOWN_TIME=' /etc/kbd/config; then
      sed -i 's/^POWERDOWN_TIME=.*/POWERDOWN_TIME=0/' /etc/kbd/config
    else
      echo 'POWERDOWN_TIME=0' >> /etc/kbd/config
    fi
    log_info "Configured console blanking and powerdown timers to 0"
  fi

  local lightdm_dir
  lightdm_dir=$(dirname "$LIGHTDM_NOBLANK_FILE")
  if [[ -d "$lightdm_dir" ]]; then
    cat <<'CFG' > "$LIGHTDM_NOBLANK_FILE"
[Seat:*]
xserver-command=X -s 0 -dpms
CFG
    log_info "Configured LightDM to disable DPMS and screen blanking"
  fi

  return 0
}
