# >>> pi-task
# id: remove_bloat
# version: 1.1.0
# description: Remove bundled educational/demo packages
# category: packages
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register remove_bloat \
  description="Remove bundled educational/demo packages" \
  category=packages \
  version=1.1.0 \
  default_enabled=1

run_remove_bloat() {
  local -a patterns=(
    'bluej'
    'claws-mail'
    'code-the-classics'*
    'geany'
    'greenfoot'
    'libreoffice-*'
    'minecraft-pi'
    'nodered'
    'nuscratch'
    'python-games'
    'raspberrypi-connect'
    'rpi-connect'
    'rpi-connect-server'
    'scratch'
    'scratch2'
    'scratch3'
    'sense-hat'
    'smartsim'
    'sonic-pi'
    'thonny'
    'wolfram-engine'
  )
  declare -A unique_packages=()
  local pattern pkg
  for pattern in "${patterns[@]}"; do
    while IFS= read -r pkg; do
      [[ -n "$pkg" ]] || continue
      unique_packages[$pkg]=1
    done < <(dpkg-query -W -f='${Package}\n' "$pattern" 2>/dev/null || true)
  done
  local -a to_remove=()
  for pkg in "${!unique_packages[@]}"; do
    to_remove+=("$pkg")
  done
  if ((${#to_remove[@]} == 0)); then
    log_info "No optional desktop packages detected"
    return 0
  fi
  log_info "Purging packages: ${to_remove[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get purge -y "${to_remove[@]}"
  DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
  DEBIAN_FRONTEND=noninteractive apt-get clean
}
