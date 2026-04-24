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

# Widget sizes. Defaults fit an 80x25 console; pi_tui_resize() scales
# them up toward the real terminal size when whiptail launches, so
# long descriptions stop getting truncated on a wide terminal.
PI_WHIP_HEIGHT=22
PI_WHIP_WIDTH=78
PI_WHIP_MENU_ROWS=12

# Recompute the three widget sizes from the live terminal. Clamped so
# we never render tinier than 80x24 (unreadable) or wider than 160
# columns (whiptail lines wrap awkwardly past that).
pi_tui_resize() {
  local cols lines
  cols=$(tput cols 2>/dev/null || echo 80)
  lines=$(tput lines 2>/dev/null || echo 24)
  local w=$((cols - 4))
  (( w < 78 )) && w=78
  (( w > 160 )) && w=160
  local h=$((lines - 2))
  (( h < 22 )) && h=22
  (( h > 40 )) && h=40
  local rows=$((h - 10))
  (( rows < 10 )) && rows=10
  (( rows > 24 )) && rows=24
  PI_WHIP_WIDTH=$w
  PI_WHIP_HEIGHT=$h
  PI_WHIP_MENU_ROWS=$rows
}

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

# Return 0 when the task's gate_var is set to an "enabled" value. Used
# by the category checklist to pre-tick items the operator opted into
# on a previous run (loaded from config.yaml) or via a CLI flag on
# this invocation. Handles both binary (INSTALL_TAILSCALE=1) and
# string (REQUESTED_HOSTNAME=pi5) gates.
_pi_tui_gate_active() {
  case "$1" in
    ssh_import)
      [[ -n "${SSH_IMPORT_GITHUB:-}" || -n "${SSH_IMPORT_URL:-}" ]]
      return
      ;;
    wifi_bt_power)
      [[ ${WIFI_POWERSAVE_OFF:-0} -ne 0 || ${DISABLE_BLUETOOTH:-0} -ne 0 ]]
      return
      ;;
    zram)
      [[ ${INSTALL_ZRAM:-0} -ne 0 || "${ZRAM_ALGO_OVERRIDE:-}" == "disabled" ]]
      return
      ;;
  esac
  local gate=${PI_TASK_GATE_VAR[$1]:-}
  [[ -z "$gate" ]] && return 1
  local val=${!gate:-}
  case $val in
    ""|0) return 1 ;;
    *)    return 0 ;;
  esac
}

# Build a whiptail checklist for a category of tasks. Arguments:
#   $1 — category name (matches PI_TASK_CATEGORY values)
#   $2 — screen title
_pi_tui_category() {
  local category=$1
  local title=$2
  local -a items=()
  local tid state_status on already_done
  for tid in "${PI_TASK_ORDER[@]}"; do
    if [[ "${PI_TASK_CATEGORY[$tid]}" != "$category" ]]; then
      continue
    fi
    state_status=""
    already_done=0
    if get_task_state "$tid"; then
      # Render `(completed 2026-04-19)` when we have a timestamp, else
      # just `(completed)`. Non-"completed" statuses (failed, pending)
      # show verbatim so operators can distinguish them at a glance.
      if [[ "$TASK_STATE_STATUS" == "completed" ]]; then
        already_done=1
        local iso_date="${TASK_STATE_TIMESTAMP%%T*}"
        if [[ -n "$iso_date" ]]; then
          state_status=" (completed $iso_date)"
        else
          state_status=" (completed)"
        fi
      else
        state_status=" ($TASK_STATE_STATUS)"
      fi
    fi
    if [[ -n "${PI_TUI_SELECTED[$tid]:-}" ]]; then
      on=ON
    elif _pi_tui_gate_active "$tid"; then
      # Gate variable says "enabled" — either from config.yaml (the
      # user opted in on a previous run) or from a CLI flag on this
      # invocation. Pre-tick so the operator sees their prior choices
      # reflected and can confirm-or-change without re-selecting from
      # scratch. Applies whether or not the task has already run.
      on=ON
    elif [[ $already_done -eq 1 ]]; then
      # Keep previously-completed tasks pre-ticked across TUI sessions
      # so a follow-up run starts from the operator's current state
      # instead of looking like everything reset to defaults.
      on=ON
    elif [[ ${PI_TASK_DEFAULT[$tid]:-1} == "1" && $already_done -eq 0 ]]; then
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
  # Remember that this category was visited. _pi_tui_apply clears gates
  # only for visited categories, so un-ticking an item actually shrinks
  # the applied set — without wiping state for categories the operator
  # never opened.
  PI_TUI_VISITED_CATEGORIES[$category]=1
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
    # Reject shell metacharacters / path traversal BEFORE the file test
    # so a crafted entry like "../etc/passwd" can't sneak past. Mirrors
    # the --timezone CLI path in pi-optimiser.sh.
    if ! validate_timezone_name "$tz"; then
      _whiptail --title "Timezone" --msgbox "Invalid zone name: $tz (expected IANA zone like Europe/London)" 8 60
      return 0
    fi
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
  local url url_lower
  url=$(_whiptail --title "NGINX reverse proxy" \
    --inputbox "Backend URL, or off/disable/disabled to tear it down:" 10 60 "$default" \
    3>&1 1>&2 2>&3) || return 0
  # Empty clears the setting; the disable sentinels match CLI/runtime
  # handling in parse_args()/run_proxy(). Any other value must survive
  # the same injection-safe validator used before writing nginx config.
  url_lower=${url,,}
  if [[ -n "$url" ]]; then
    case "$url_lower" in
      off|false|disable|disabled|null|none)
        ;;
      *)
        if ! validate_proxy_backend_url "$url"; then
          _whiptail --title "NGINX reverse proxy" --msgbox \
            "Invalid backend URL: $url\n\nExpected http(s)://host[:port][/path] or off/disable/disabled." 10 60
          return 0
        fi
        ;;
    esac
  fi
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
  # Apply the same validator the --locale CLI path uses. /etc/default/locale
  # is shell-sourced by /etc/profile, so an unvalidated value written here
  # would be a code-exec vector on next login.
  if [[ -n "$loc" ]] && ! validate_locale "$loc"; then
    _whiptail --title "System locale" --msgbox \
      "Invalid locale: $loc\n\nExpected ll_CC[.encoding][@modifier], e.g. en_GB.UTF-8." 10 60
    return 0
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
      # Match --ssh-import-github CLI validation so a crafted handle
      # can't reach curl unescaped.
      if [[ -n "$name" ]] && ! validate_github_handle "$name"; then
        _whiptail --title "SSH key import" --msgbox \
          "Invalid GitHub handle: $name\n\n1..39 chars, alphanumerics and single hyphens, no leading/trailing hyphen." 10 60
        return 0
      fi
      SSH_IMPORT_GITHUB=$name
      ;;
    url)
      local url
      url=$(_whiptail --inputbox "https:// URL to authorized_keys:" 10 60 \
        "${SSH_IMPORT_URL:-}" 3>&1 1>&2 2>&3) || return 0
      if [[ -n "$url" ]] && ! validate_https_url "$url"; then
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
  local tid gate
  local _preserve_wifi=0 _preserve_bt=0 _preserve_zram_disabled=0
  if [[ -n "${PI_TUI_SELECTED[wifi_bt_power]:-}" ]]; then
    _preserve_wifi=${WIFI_POWERSAVE_OFF:-0}
    _preserve_bt=${DISABLE_BLUETOOTH:-0}
  fi
  if [[ -n "${PI_TUI_SELECTED[zram]:-}" && "${ZRAM_ALGO_OVERRIDE:-}" == "disabled" ]]; then
    _preserve_zram_disabled=1
  fi
  # For every category the operator visited, reset that category's
  # binary gates to 0 first. Ticked items in the loop below then
  # flip back to 1. Un-visited categories keep their state so
  # saving YAML after a narrow edit doesn't clobber prior opt-ins.
  for tid in "${PI_TASK_ORDER[@]}"; do
    [[ -n "${PI_TUI_VISITED_CATEGORIES[${PI_TASK_CATEGORY[$tid]}]:-}" ]] || continue
    case "$tid" in
      wifi_bt_power)
        WIFI_POWERSAVE_OFF=0
        DISABLE_BLUETOOTH=0
        continue
        ;;
      zram)
        INSTALL_ZRAM=0
        ZRAM_ALGO_OVERRIDE=""
        continue
        ;;
    esac
    gate=${PI_TASK_GATE_VAR[$tid]:-}
    case $gate in
      ""|REQUESTED_HOSTNAME|REQUESTED_TIMEZONE|REQUESTED_LOCALE|PROXY_BACKEND|SSH_IMPORT_GITHUB|SSH_IMPORT_URL)
        : # No gate or value-typed — don't reset.
        ;;
      *)
        printf -v "$gate" '%s' 0
        ;;
    esac
  done
  ONLY_TASKS=()
  for tid in "${PI_TASK_ORDER[@]}"; do
    [[ -n "${PI_TUI_SELECTED[$tid]:-}" ]] || continue
    ONLY_TASKS+=("$tid")
    case "$tid" in
      wifi_bt_power)
        if [[ ${WIFI_POWERSAVE_OFF:-0} -eq 0 && ${DISABLE_BLUETOOTH:-0} -eq 0 ]]; then
          if [[ $_preserve_wifi -eq 1 ]]; then
            WIFI_POWERSAVE_OFF=1
          fi
          if [[ $_preserve_bt -eq 1 ]]; then
            DISABLE_BLUETOOTH=1
          fi
          if [[ $_preserve_wifi -eq 0 && $_preserve_bt -eq 0 ]]; then
            WIFI_POWERSAVE_OFF=1
          fi
        fi
        continue
        ;;
      zram)
        if [[ $_preserve_zram_disabled -eq 1 ]]; then
          ZRAM_ALGO_OVERRIDE=disabled
        else
          INSTALL_ZRAM=1
        fi
        continue
        ;;
    esac
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

# Render `print_status` output into a scrollable textbox. Wrapped in its
# own function so the RETURN trap fires when this function returns (not
# only when pi_tui_main returns), guaranteeing the tempfile is cleaned
# even on whiptail error. A matching EXIT trap catches Ctrl+C while the
# textbox is up.
_pi_tui_show_status() {
  local tmp
  tmp=$(mktemp -t pi-optimiser-tui.XXXXXX) || return 0
  # shellcheck disable=SC2064
  trap "rm -f -- '$tmp'" RETURN
  # shellcheck disable=SC2064
  trap "rm -f -- '$tmp'; trap - EXIT; exit 130" INT
  print_status > "$tmp" 2>&1
  _whiptail --title "Status" --textbox "$tmp" $PI_WHIP_HEIGHT $PI_WHIP_WIDTH || true
  trap - INT
}

# Render `pi_check_update` into a textbox and, on confirm, stream
# `pi_self_update` into a programbox. Same trap discipline as above.
_pi_tui_show_update() {
  local tmp
  tmp=$(mktemp -t pi-optimiser-tui.XXXXXX) || return 0
  # shellcheck disable=SC2064
  trap "rm -f -- '$tmp'" RETURN
  # shellcheck disable=SC2064
  trap "rm -f -- '$tmp'; trap - EXIT; exit 130" INT
  pi_check_update > "$tmp" 2>&1 || true
  _whiptail --title "Check for updates" --textbox "$tmp" 18 78 || true
  trap - INT
  if _whiptail --yesno "Run --update now?" 8 40; then
    pi_self_update 2>&1 | tail -40 | _whiptail --title "Update result" --programbox 20 78
  fi
}

pi_tui_main() {
  # Sanity-check environment up front.
  if ! pi_tui_available; then
    echo "pi-optimiser: whiptail unavailable or terminal unsupported; cannot launch TUI." >&2
    return 1
  fi
  pi_tui_resize
  declare -gA PI_TUI_SELECTED=()
  declare -gA PI_TUI_VISITED_CATEGORIES=()
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
        display    "Boot config, screen blanking, quiet boot, LEDs" \
        security   "SSH hardening, key import, firewall" \
        packages   "CLI, diagnostic, and monitoring bundles" \
        services   "Extra services (Docker, Raspberry Pi Connect)" \
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
      hardware)
        _pi_tui_category hardware-clocks "Hardware & clocks"
        if [[ -n "${PI_TUI_SELECTED[oc_conservative]:-}" && -n "${PI_TUI_SELECTED[underclock]:-}" ]]; then
          local _clk
          _clk=$(_whiptail --title "Clock conflict" \
            --radiolist "Overclock and underclock both selected — pick one:" \
            12 64 2 \
            oc_conservative "Conservative overclock (faster)"  ON \
            underclock      "Low-power underclock (cooler/slower)" OFF \
            3>&1 1>&2 2>&3) || true
          case ${_clk//\"/} in
            oc_conservative) unset 'PI_TUI_SELECTED[underclock]' ;;
            underclock)      unset 'PI_TUI_SELECTED[oc_conservative]' ;;
          esac
        fi
        ;;
      display)   _pi_tui_category display          "Display" ;;
      security)  _pi_tui_category security         "Security" ;;
      packages)  _pi_tui_category packages         "Packages" ;;
      services)  _pi_tui_category integrations     "Extra services" ;;
      firmware)  _pi_tui_category firmware-eeprom  "Firmware & EEPROM" ;;
      values)    _pi_tui_forms_menu ;;
      status)   _pi_tui_show_status ;;
      apply)
        if _pi_tui_apply && [[ ${PI_TUI_READY_TO_RUN:-0} -eq 1 ]]; then
          return 0
        fi
        ;;
      update)   _pi_tui_show_update ;;
      exit|"") return 1 ;;
    esac
  done
  return 1
}
