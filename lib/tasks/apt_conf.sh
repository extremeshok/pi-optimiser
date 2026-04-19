# >>> pi-task
# id: apt_conf
# version: 1.1.0
# description: Reduce apt cache usage and auto updates
# category: system
# default_enabled: 1
# power_sensitive: 0
# <<< pi-task

pi_task_register apt_conf \
  description="Reduce apt cache usage and auto updates" \
  category=system \
  version=1.1.0 \
  default_enabled=1

run_apt_conf() {
  cat <<'CFG' > "$APT_CONF_FILE"
APT::Install-Recommends "0";
APT::Install-Suggests "0";
APT::Get::AutomaticRemove "1";
APT::Periodic::Enable "0";
Binary::apt::APT::Keep-Downloaded-Packages "false";
Acquire::Languages "none";
CFG
  unit_disable_now apt-daily.timer
  unit_disable_now apt-daily-upgrade.timer
  unit_mask apt-daily.service
  unit_mask apt-daily-upgrade.service
  DEBIAN_FRONTEND=noninteractive apt-get clean
}
