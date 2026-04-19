# >>> pi-task
# id: cli_bundle_modern
# version: 1.0.0
# description: Install a modern CLI bundle (ncdu, ripgrep, fd-find, bat, neovim)
# category: packages
# default_enabled: 0
# flags: --install-cli-modern
# gate_var: INSTALL_CLI_MODERN
# <<< pi-task

pi_task_register cli_bundle_modern \
  description="Install a modern CLI bundle (ncdu, ripgrep, fd-find, bat, neovim)" \
  category=packages \
  version=1.0.0 \
  default_enabled=0 \
  flags="--install-cli-modern" \
  gate_var=INSTALL_CLI_MODERN

run_cli_bundle_modern() {
  if [[ ${INSTALL_CLI_MODERN:-0} -eq 0 ]]; then
    log_info "Modern CLI bundle not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  ensure_packages ncdu mtr-tiny ripgrep fd-find bat neovim
  log_info "Modern CLI bundle installed"
  write_json_field "$CONFIG_OPTIMISER_STATE" "packages.cli_modern" "installed"
}
