# >>> pi-task
# id: remove_bloat
# version: 1.2.0
# description: Remove preinstalled demo and educational packages
# category: packages
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register remove_bloat \
  description="Remove preinstalled demo and educational packages" \
  category=packages \
  version=1.2.0 \
  default_enabled=1

# Decide whether the current run counts as "non-desktop" — kiosk /
# server / headless-iot all qualify, and so does an explicit
# --remove-cups or KEEP_SCREEN_BLANKING=1 flag. Plain runs (no
# profile selected) leave CUPS alone so we don't break printing on
# someone's desktop Pi by surprise.
_remove_bloat_is_headless() {
  [[ ${REMOVE_CUPS:-0} -eq 1 ]] && return 0
  [[ ${KEEP_SCREEN_BLANKING:-0} -eq 1 ]] && return 0
  case ${PI_PROFILE:-} in
    kiosk|server|headless-iot) return 0 ;;
  esac
  return 1
}

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
  # CUPS + printer-driver packages eat ~100 MB and pull avahi / colord
  # on desktop Pi OS images. Nothing in a kiosk / server / IoT build
  # prints, so purge them — unless a plain run where the operator
  # didn't pick a non-desktop profile (then leave it alone).
  if _remove_bloat_is_headless; then
    patterns+=(
      'cups'
      'cups-*'
      'cups-bsd'
      'cups-client'
      'cups-common'
      'cups-daemon'
      'cups-filters'
      'cups-filters-core-drivers'
      'cups-ipp-utils'
      'cups-server-common'
      'libcups2'
      'libcupsfilters*'
      'libcupsimage2'
      'printer-driver-*'
      'system-config-printer-common'
      'system-config-printer-udev'
      'hplip'
      'hplip-data'
      'foomatic-db-compressed-ppds'
    )
  fi
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
