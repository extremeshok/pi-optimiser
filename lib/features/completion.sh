# ======================================================================
# lib/features/completion.sh — shell-completion generators
#
# Emits a bash or zsh completion script on stdout. The generated
# script completes:
#   - long flags from a hard-coded list (kept in sync with parse_args
#     in pi-optimiser.sh; there is no registry-based generator yet)
#   - task ids (from `pi-optimiser --list-tasks`) after --only / --skip / --undo
#   - profile names after --profile
#   - file paths after --config / --validate-config / --restore
# ======================================================================

pi_emit_completion_bash() {
  cat <<'BASH'
# pi-optimiser bash completion
_pi_optimiser() {
  local cur prev words cword
  _init_completion || return

  local flags="
    --force --dry-run --status --list-tasks --list-profiles
    --report --snapshot --restore --undo --check-update --update
    --enable-update-timer --disable-update-timer --require-signature
    --uninstall --migrate --rollback --tui --no-tui --yes
    --non-interactive --config --no-config --validate-config
    --output --profile --only --skip
    --install-tailscale --install-docker --install-zram
    --install-wireguard --allow-both-vpn --install-node-exporter
    --install-smartmontools --install-cli-modern --install-net-diag
    --enable-dns-cache --overclock-conservative --underclock
    --pi5-fan-profile --pcie-gen3 --enable-watchdog --secure-ssh
    --firmware-update --eeprom-update --ssh-import-github
    --ssh-import-url --hostname --timezone --locale --proxy-backend
    --zram-algo --temp-limit --temp-soft-limit --initial-turbo
    --wifi-powersave-off --disable-bluetooth --keep-screen-blanking
    --docker-buildx-multiarch --docker-cgroupv2
    --watch --diff --no-metrics --metrics-path --freeze-task
    --self-test --show-config --reboot
    --install-firewall --power-off-halt --nvme-tune --quiet-boot
    --disable-leds --install-pi-connect --remove-cups
    --headless-gpu-mem --install-chrony --disable-ipv6
    --usb-uas-quirks --usb-uas-extra --install-hailo
    --completion --help --version
  "

  case "$prev" in
    --only|--skip|--undo|--freeze-task)
      local tasks
      tasks=$(pi-optimiser --list-tasks 2>/dev/null \
        | awk 'NR>2 && $1 ~ /^[a-z]/ {print $1}')
      COMPREPLY=( $(compgen -W "$tasks" -- "$cur") )
      return 0
      ;;
    --metrics-path)
      _filedir
      return 0
      ;;
    --profile)
      COMPREPLY=( $(compgen -W "kiosk server desktop headless-iot" -- "$cur") )
      return 0
      ;;
    --output)
      COMPREPLY=( $(compgen -W "text json" -- "$cur") )
      return 0
      ;;
    --zram-algo)
      COMPREPLY=( $(compgen -W "lz4 zstd disabled" -- "$cur") )
      return 0
      ;;
    --config|--validate-config|--restore)
      _filedir
      return 0
      ;;
    --completion)
      COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
      return 0
      ;;
  esac

  if [[ $cur == -* ]]; then
    COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
  fi
}
complete -F _pi_optimiser pi-optimiser
complete -F _pi_optimiser pi-optimiser.sh
BASH
}

pi_emit_completion_zsh() {
  cat <<'ZSH'
#compdef pi-optimiser pi-optimiser.sh
# pi-optimiser zsh completion
_pi_optimiser() {
  local -a flags
  flags=(
    '--force[re-run tasks even if completed]'
    '--dry-run[log intended actions only]'
    '--status[print task status table]'
    '--list-tasks[show available tasks]'
    '--list-profiles[show built-in profiles]'
    '--report[print state report]'
    '--snapshot[tar current config into /etc/pi-optimiser/snapshots]'
    '--restore[restore a snapshot tarball]:archive:_files'
    '--undo[roll back a task]:task:->tasks'
    '--check-update[check for updates (exit 10 if ahead)]'
    '--update[self-update from the configured ref]'
    '--enable-update-timer[install daily update timer]'
    '--disable-update-timer[remove update timer]'
    '--require-signature[require minisign signature for --update]'
    '--uninstall[remove /opt/pi-optimiser]'
    '--migrate[promote a dev checkout to an install]'
    '--rollback[flip current to the previous release]'
    '--tui[launch whiptail TUI]'
    '--no-tui[suppress TUI]'
    '--yes[assume yes to prompts]'
    '--non-interactive[alias of --yes]'
    '--config[read YAML config]:path:_files'
    '--no-config[ignore /etc/pi-optimiser/config.yaml]'
    '--validate-config[parse-check a YAML config]:path:_files'
    '--output[output format]:fmt:(text json)'
    '--profile[apply flag bundle]:profile:(kiosk server desktop headless-iot)'
    '--only[restrict to task]:task:->tasks'
    '--skip[skip a task]:task:->tasks'
    '--zram-algo[ZRAM algorithm]:algo:(lz4 zstd disabled)'
    '--temp-limit[hard thermal limit in degrees C]:celsius:'
    '--temp-soft-limit[soft thermal limit in degrees C]:celsius:'
    '--initial-turbo[early-boot turbo seconds]:seconds:'
    '--watch[re-run on config.yaml changes]'
    '--diff[preview config.txt/cmdline.txt edits]'
    '--no-metrics[skip Prometheus textfile output]'
    '--metrics-path[override Prometheus output path]:path:_files'
    '--freeze-task[treat a task as completed]:task:->tasks'
    '--self-test[run task preconditions read-only]'
    '--show-config[print effective config]'
    '--reboot[reboot immediately after a successful run (shutdown -r)]'
    '--install-firewall[install and enable UFW]'
    '--install-tailscale[install Tailscale mesh VPN]'
    '--install-docker[install Docker CE]'
    '--install-zram[enable ZRAM compressed swap]'
    '--install-wireguard[install WireGuard tooling]'
    '--allow-both-vpn[permit Tailscale and WireGuard together]'
    '--install-node-exporter[install prometheus-node-exporter]'
    '--install-smartmontools[install smartmontools + smartd]'
    '--install-cli-modern[install modern CLI bundle]'
    '--install-net-diag[install network-diagnostic bundle]'
    '--enable-dns-cache[install local DNS resolver]'
    '--overclock-conservative[safe overclock preset]'
    '--underclock[reduce clocks for thermals]'
    '--pi5-fan-profile[Pi 5: cooler fan curve]'
    '--pcie-gen3[Pi 5: PCIe Gen3 for NVMe HATs]'
    '--enable-watchdog[enable hardware watchdog]'
    '--secure-ssh[harden sshd_config]'
    '--firmware-update[run rpi-update]'
    '--eeprom-update[update Pi 5 EEPROM]'
    '--ssh-import-github[import SSH keys from GitHub]:user:'
    '--ssh-import-url[import SSH keys from URL]:url:'
    '--hostname[set system hostname]:hostname:'
    '--timezone[set system timezone]:tz:'
    '--locale[set system locale]:locale:'
    '--proxy-backend[container proxy backend]:backend:'
    '--wifi-powersave-off[disable wifi power saving]'
    '--disable-bluetooth[disable bluetooth radio]'
    '--keep-screen-blanking[do not disable screen blanking]'
    '--docker-buildx-multiarch[enable Docker buildx multiarch]'
    '--docker-cgroupv2[enable cgroup v2 for Docker]'
    '--power-off-halt[Pi 5 EEPROM: cut 3V3 on shutdown]'
    '--nvme-tune[disable NVMe APST for HAT compatibility]'
    '--quiet-boot[hide splash and silence kernel log]'
    '--disable-leds[turn off activity/power/ethernet LEDs]'
    '--install-pi-connect[install Raspberry Pi Connect]'
    '--remove-cups[purge CUPS and printer packages]'
    '--headless-gpu-mem[Pi <=4: shrink GPU mem split to 16 MB]'
    '--install-chrony[replace timesyncd with chrony]'
    '--disable-ipv6[disable IPv6 via sysctl]'
    '--usb-uas-quirks[disable UAS on known-bad USB-SATA adapters]'
    '--usb-uas-extra[extra VID:PID pairs for UAS quirks]:pairs:'
    '--install-hailo[Pi 5: install Hailo NPU drivers]'
    '--completion[emit completion script]:shell:(bash zsh)'
    '--help[show help]'
    '--version[show version]'
  )
  _arguments -s $flags
  case $state in
    tasks)
      local -a tasks
      tasks=( ${(f)"$(pi-optimiser --list-tasks 2>/dev/null | awk 'NR>2 && $1 ~ /^[a-z]/ {print $1}')"} )
      _describe 'task' tasks
      ;;
  esac
}
_pi_optimiser "$@"
ZSH
}
