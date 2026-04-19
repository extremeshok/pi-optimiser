# ======================================================================
# lib/ui/tui.sh — whiptail-based interactive UI
#
# Functions: pi_tui_available, pi_tui_main, pi_tui_should_launch
#
# Design: the TUI never calls task runners directly. It edits in-memory
# globals (the same ones CLI flags set) and then invokes the existing
# task-dispatch loop from main(). Writing the active config to
# /etc/pi-optimiser/config.yaml is left to pi_config_save so a later
# CLI run with --config <file> reproduces the same session.
# ======================================================================

# Widget sizes. These play nicely with a 25x80 console.
PI_WHIP_HEIGHT=22
PI_WHIP_WIDTH=78
PI_WHIP_MENU_ROWS=12

# Readable palette matching raspi-config on Pi OS.
PI_NEWT_COLORS='
root=,blue
window=,lightgray
border=black,lightgray
title=black,lightgray
button=black,cyan
actbutton=white,blue
checkbox=black,lightgray
actcheckbox=black,cyan
listbox=black,lightgray
actlistbox=black,cyan
label=black,lightgray
'

pi_tui_available() {
  command -v whiptail >/dev/null 2>&1 || return 1
  # whiptail renders garbage on a non-capable terminal; bail out so
  # the caller falls back to plain stdout.
  case "${TERM:-dumb}" in
    dumb|"") return 1 ;;
  esac
  return 0
}

# Decide if we should launch the TUI given current CLI flags + TTY.
pi_tui_should_launch() {
  # Explicit user preference wins both ways.
  if [[ ${PI_FORCE_TUI:-0} -eq 1 ]]; then
    return 0
  fi
  if [[ ${PI_NO_TUI:-0} -eq 1 || ${PI_NON_INTERACTIVE:-0} -eq 1 ]]; then
    return 1
  fi
  # Need whiptail and interactive stdin/stdout.
  if ! pi_tui_available; then
    return 1
  fi
  if [[ ! -t 0 || ! -t 1 ]]; then
    return 1
  fi
  # Skip TUI when the user clearly wants a batch action.
  local f
  for f in "${PI_CLI_ACTION_FLAGS[@]:-}"; do
    [[ -z "$f" ]] && continue
    if [[ " $PI_ARGV_RAW " == *" $f "* ]]; then
      return 1
    fi
  done
  return 0
}

_whiptail() {
  NEWT_COLORS="$PI_NEWT_COLORS" whiptail \
    --backtitle "pi-optimiser $SCRIPT_VERSION | ${SYSTEM_MODEL:-unknown} | $(hostname)" \
    "$@"
}

_pi_tui_suggest_profile() {
  local suggestion="custom"
  local boot=${SYSTEM_BOOT_DEVICE:-}
  local hdmi=""
  if compgen -G "/sys/class/drm/card*-HDMI*" >/dev/null 2>&1; then
    if grep -qli connected /sys/class/drm/card*-HDMI*/status 2>/dev/null; then
      hdmi=connected
    fi
  fi
  if systemctl is-enabled lightdm >/dev/null 2>&1; then
    suggestion=desktop
  elif [[ ${SYSTEM_PI_GEN:-} == "zero2" || ${SYSTEM_RAM_MB:-0} -lt 1024 ]]; then
    suggestion=headless-iot
  elif [[ "$boot" == "nvme" && -z "$hdmi" ]]; then
    suggestion=server
  elif [[ -n "$hdmi" ]]; then
    suggestion=kiosk
  fi
  echo "$suggestion"
}

_pi_tui_welcome() {
  local config=/etc/pi-optimiser/config.yaml
  if [[ -f "$config" ]]; then
    return 0  # returning user, skip the welcome wizard
  fi
  local suggestion
  suggestion=$(_pi_tui_suggest_profile)
  local choice
  choice=$(_whiptail --title "pi-optimiser — Welcome" \
    --radiolist "Detected: ${SYSTEM_MODEL:-?}, ${SYSTEM_RAM_MB:-0}MB.\nSuggested profile: $suggestion\nPick a starting profile (you can customise next):" \
    $PI_WHIP_HEIGHT $PI_WHIP_WIDTH 5 \
    kiosk        "HDMI kiosk — screen on, Wi-Fi always up"     "$([[ $suggestion == kiosk ]] && echo ON || echo OFF)" \
    server       "Headless server — tmpfs, ZRAM, hardened SSH" "$([[ $suggestion == server ]] && echo ON || echo OFF)" \
    desktop      "GUI Pi — modern CLI, keep swap"              "$([[ $suggestion == desktop ]] && echo ON || echo OFF)" \
    headless-iot "Zero 2 / IoT — watchdog, no BT, underclock"  "$([[ $suggestion == headless-iot ]] && echo ON || echo OFF)" \
    custom       "Start from zero"                             "$([[ $suggestion == custom ]] && echo ON || echo OFF)" \
    3>&1 1>&2 2>&3) || return 1
  if [[ -n "$choice" && "$choice" != "custom" ]]; then
    pi_apply_profile "$choice"
  fi
}

# Build a whiptail checklist for a category of tasks. Arguments:
#   $1 — category name (matches PI_TASK_CATEGORY values)
#   $2 — screen title
_pi_tui_category() {
  local category=$1
  local title=$2
  local -a items=()
  local tid state_status on
  for tid in "${PI_TASK_ORDER[@]}"; do
    if [[ "${PI_TASK_CATEGORY[$tid]}" != "$category" ]]; then
      continue
    fi
    state_status=""
    if get_task_state "$tid"; then
      state_status=" (last ${TASK_STATE_STATUS})"
    fi
    if [[ -n "${PI_TUI_SELECTED[$tid]:-}" ]]; then
      on=ON
    elif [[ ${PI_TASK_DEFAULT[$tid]:-1} == "1" && "$state_status" != " (last completed)" ]]; then
      on=ON
    else
      on=OFF
    fi
    items+=("$tid" "${PI_TASK_DESC[$tid]}${state_status}" "$on")
  done
  if (( ${#items[@]} == 0 )); then
    return 0
  fi
  local selected
  selected=$(_whiptail --title "$title" \
    --checklist "SPACE to toggle, ENTER to confirm" \
    $PI_WHIP_HEIGHT $PI_WHIP_WIDTH $PI_WHIP_MENU_ROWS \
    "${items[@]}" \
    3>&1 1>&2 2>&3) || return 0
  # Clear existing selections in this category.
  local id
  for id in "${PI_TASK_ORDER[@]}"; do
    if [[ "${PI_TASK_CATEGORY[$id]}" == "$category" ]]; then
      unset 'PI_TUI_SELECTED[$id]'
    fi
  done
  for id in $selected; do
    id=${id//\"/}
    PI_TUI_SELECTED[$id]=1
  done
}

_pi_tui_form_timezone() {
  local default=${REQUESTED_TIMEZONE:-$(cat /etc/timezone 2>/dev/null || echo UTC)}
  local tz
  tz=$(_whiptail --title "Timezone" \
    --inputbox "IANA zone (e.g. Europe/London):" 10 60 "$default" \
    3>&1 1>&2 2>&3) || return 0
  if [[ -n "$tz" ]]; then
    if [[ -f "/usr/share/zoneinfo/$tz" ]]; then
      REQUESTED_TIMEZONE=$tz
    else
      _whiptail --title "Timezone" --msgbox "Unknown zone: $tz" 8 50
    fi
  fi
}

_pi_tui_form_hostname() {
  local default=${REQUESTED_HOSTNAME:-$(hostname 2>/dev/null)}
  local name
  name=$(_whiptail --title "Hostname" \
    --inputbox "Hostname (RFC 1123 label; a-z 0-9 and '-', 1..63 chars):" 10 60 "$default" \
    3>&1 1>&2 2>&3) || return 0
  if [[ -n "$name" ]]; then
    if validate_hostname "$name"; then
      REQUESTED_HOSTNAME=$name
    else
      _whiptail --title "Hostname" --msgbox "Invalid hostname: $name" 8 50
    fi
  fi
}

_pi_tui_form_proxy() {
  local default=${PROXY_BACKEND:-}
  local url
  url=$(_whiptail --title "NGINX reverse proxy" \
    --inputbox "Backend URL, or 'disabled' to tear it down:" 10 60 "$default" \
    3>&1 1>&2 2>&3) || return 0
  PROXY_BACKEND=$url
}

_pi_tui_form_locale() {
  local default=${REQUESTED_LOCALE:-}
  local loc
  loc=$(_whiptail --title "System locale" \
    --menu "Pick a locale (or choose Other to type):" $PI_WHIP_HEIGHT $PI_WHIP_WIDTH 10 \
      "en_GB.UTF-8" "British English" \
      "en_US.UTF-8" "US English" \
      "de_DE.UTF-8" "Deutsch" \
      "fr_FR.UTF-8" "Français" \
      "es_ES.UTF-8" "Español" \
      "it_IT.UTF-8" "Italiano" \
      "nl_NL.UTF-8" "Nederlands" \
      "pt_BR.UTF-8" "Português (BR)" \
      "ja_JP.UTF-8" "Japanese" \
      "zh_CN.UTF-8" "Simplified Chinese" \
      "other"       "Type a locale manually…" \
    3>&1 1>&2 2>&3) || return 0
  if [[ "$loc" == "other" ]]; then
    loc=$(_whiptail --title "System locale" \
      --inputbox "Locale code (e.g. en_ZA.UTF-8):" 10 60 "$default" \
      3>&1 1>&2 2>&3) || return 0
  fi
  REQUESTED_LOCALE=$loc
}

_pi_tui_form_ssh_import() {
  local choice
  choice=$(_whiptail --title "SSH key import" \
    --menu "Where should authorized_keys be pulled from?" 14 60 3 \
      github  "From a GitHub username (https://github.com/<u>.keys)" \
      url     "From an arbitrary https:// URL" \
      cancel  "Skip SSH key import" \
    3>&1 1>&2 2>&3) || return 0
  case $choice in
    github)
      local name
      name=$(_whiptail --inputbox "GitHub username:" 10 60 \
        "${SSH_IMPORT_GITHUB:-}" 3>&1 1>&2 2>&3) || return 0
      SSH_IMPORT_GITHUB=$name
      ;;
    url)
      local url
      url=$(_whiptail --inputbox "https:// URL to authorized_keys:" 10 60 \
        "${SSH_IMPORT_URL:-}" 3>&1 1>&2 2>&3) || return 0
      if [[ -n "$url" && "$url" != https://* ]]; then
        _whiptail --msgbox "URL must begin with https://" 8 50
        return 0
      fi
      SSH_IMPORT_URL=$url
      ;;
  esac
}

_pi_tui_forms_menu() {
  local choice
  while true; do
    choice=$(_whiptail --title "Values" \
      --menu "Set values for opt-in tasks (current values shown):" \
        $PI_WHIP_HEIGHT $PI_WHIP_WIDTH 8 \
        hostname  "Hostname: ${REQUESTED_HOSTNAME:-<unset>}" \
        timezone  "Timezone: ${REQUESTED_TIMEZONE:-<unset>}" \
        locale    "Locale: ${REQUESTED_LOCALE:-<unset>}" \
        proxy     "Proxy backend: ${PROXY_BACKEND:-<unset>}" \
        ssh_keys  "SSH import: gh=${SSH_IMPORT_GITHUB:-} url=${SSH_IMPORT_URL:-}" \
        back      "<- Back to main menu" \
      3>&1 1>&2 2>&3) || return 0
    case $choice in
      hostname) _pi_tui_form_hostname ;;
      timezone) _pi_tui_form_timezone ;;
      locale)   _pi_tui_form_locale ;;
      proxy)    _pi_tui_form_proxy ;;
      ssh_keys) _pi_tui_form_ssh_import ;;
      back|"") return 0 ;;
    esac
  done
}

_pi_tui_apply() {
  # Translate the checklist selection into --only + gate-variable flips.
  # Without the flips, each task's own gate_var check (e.g.
  # `[[ $INSTALL_TAILSCALE -eq 1 ]]`) would still see 0 and skip the
  # task with "not requested" — the exact bug a TUI is meant to avoid.
  # Value-typed gate_vars (hostnames, timezones, URLs) are set via the
  # "values" forms menu; we never coerce them to "1".
  ONLY_TASKS=()
  local tid gate
  for tid in "${PI_TASK_ORDER[@]}"; do
    [[ -n "${PI_TUI_SELECTED[$tid]:-}" ]] || continue
    ONLY_TASKS+=("$tid")
    gate=${PI_TASK_GATE_VAR[$tid]:-}
    case $gate in
      ""|REQUESTED_HOSTNAME|REQUESTED_TIMEZONE|REQUESTED_LOCALE|PROXY_BACKEND|SSH_IMPORT_GITHUB|SSH_IMPORT_URL)
        : # No gate_var, or a string-valued gate set via the forms menu.
        ;;
      *)
        printf -v "$gate" '%s' 1
        ;;
    esac
  done
  if (( ${#ONLY_TASKS[@]} == 0 )); then
    _whiptail --msgbox "No tasks selected; nothing to apply." 8 50
    return 0
  fi
  # Mutex check — same rules as the CLI path (pi_validate_mutex). On
  # conflict, show the error text and return to the main menu so the
  # operator can fix the selection instead of losing progress.
  local mutex_msg
  if mutex_msg=$(pi_validate_mutex 2>&1); then
    :
  else
    _whiptail --title "Conflicting selections" --msgbox \
      "The selected tasks conflict.\n\n${mutex_msg}\n\nUncheck one side and try again." 16 72
    return 0
  fi
  pi_config_save
  _whiptail --yesno "Apply ${#ONLY_TASKS[@]} selected task(s) now?\n\nConfig saved to /etc/pi-optimiser/config.yaml." 10 60 || return 0
  # Signal main() to fall through and run the loop.
  PI_TUI_READY_TO_RUN=1
  return 0
}

pi_tui_main() {
  # Sanity-check environment up front.
  if ! pi_tui_available; then
    echo "pi-optimiser: whiptail not installed; cannot launch TUI." >&2
    return 1
  fi
  declare -gA PI_TUI_SELECTED=()
  PI_TUI_READY_TO_RUN=0

  _pi_tui_welcome

  local choice
  while true; do
    choice=$(_whiptail --title "pi-optimiser — Main Menu" \
      --menu "SPACE scrolls, ENTER selects" \
        $PI_WHIP_HEIGHT $PI_WHIP_WIDTH $PI_WHIP_MENU_ROWS \
        storage    "Storage & filesystem tuning" \
        system     "System identity, limits, background services" \
        network    "Network stack, proxy, VPNs, DNS cache" \
        hardware   "Clocks, fan, watchdog, PCIe, EEPROM" \
        display    "Boot config + screen blanking" \
        security   "SSH hardening + key import" \
        packages   "Package bundles + integrations" \
        firmware   "Firmware + EEPROM refresh" \
        values     "Set values for opt-in tasks (hostname, TZ, …)" \
        status     "View current state + task history" \
        apply      "Apply selected tasks" \
        update     "Self-update from GitHub" \
        exit       "Quit without applying" \
      3>&1 1>&2 2>&3) || break
    case $choice in
      storage)   _pi_tui_category storage          "Storage & filesystems" ;;
      system)    _pi_tui_category system           "System" ;;
      network)   _pi_tui_category network          "Networking" ;;
      hardware)  _pi_tui_category hardware-clocks  "Hardware & clocks" ;;
      display)   _pi_tui_category display          "Display" ;;
      security)  _pi_tui_category security         "Security" ;;
      packages)  _pi_tui_category packages         "Packages" ;;
      firmware)
        _pi_tui_category firmware-eeprom "Firmware & EEPROM"
        _pi_tui_category integrations    "Integrations"
        ;;
      values)    _pi_tui_forms_menu ;;
      status)
        local tmp
        tmp=$(mktemp)
        print_status > "$tmp" 2>&1
        _whiptail --title "Status" --textbox "$tmp" $PI_WHIP_HEIGHT $PI_WHIP_WIDTH
        rm -f "$tmp"
        ;;
      apply)
        if _pi_tui_apply && [[ ${PI_TUI_READY_TO_RUN:-0} -eq 1 ]]; then
          return 0
        fi
        ;;
      update)
        local tmp
        tmp=$(mktemp)
        pi_check_update > "$tmp" 2>&1 || true
        _whiptail --title "Check for updates" --textbox "$tmp" 18 78
        rm -f "$tmp"
        if _whiptail --yesno "Run --update now?" 8 40; then
          pi_self_update 2>&1 | tail -40 | _whiptail --title "Update result" --programbox 20 78
        fi
        ;;
      exit|"") return 1 ;;
    esac
  done
  return 1
}
