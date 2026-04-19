# >>> pi-task
# id: cli_tools
# version: 1.1.0
# description: Ensure essential CLI tools are installed
# category: packages
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register cli_tools \
  description="Ensure essential CLI tools are installed" \
  category=packages \
  version=1.1.0 \
  default_enabled=1

run_cli_tools() {
  local -a packages=(
    htop
    iftop
    iotop
    locales-all
    pigz
    screen
    tmux
  )
  local -a missing=()
  local pkg
  for pkg in "${packages[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if ((${#missing[@]} == 0)); then
    log_info "Essential CLI tools already installed"
    return 0
  fi
  ensure_packages "${missing[@]}"
}
