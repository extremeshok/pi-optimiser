# >>> pi-task
# id: docker
# version: 1.2.0
# description: Install Docker Engine and enable the service
# category: integrations
# default_enabled: 0
# power_sensitive: 0
# flags: --install-docker,--docker-buildx-multiarch,--docker-cgroupv2
# gate_var: INSTALL_DOCKER
# <<< pi-task

pi_task_register docker \
  description="Install Docker Engine and enable the service" \
  category=integrations \
  version=1.2.0 \
  default_enabled=0 \
  flags="--install-docker,--docker-buildx-multiarch,--docker-cgroupv2" \
  gate_var=INSTALL_DOCKER

run_docker() {
  if [[ ${INSTALL_DOCKER:-0} -eq 0 ]]; then
    log_info "Docker install not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi
  load_os_release
  local arch repo_id repo_configured=0
  arch=$(dpkg --print-architecture)
  repo_id=$OS_ID
  if [[ $repo_id == "raspbian" || $repo_id == "debian" ]]; then
    repo_id="debian"
  elif [[ $repo_id == "ubuntu" ]]; then
    repo_id="ubuntu"
  elif [[ -n $OS_ID_LIKE && $OS_ID_LIKE == *debian* ]]; then
    repo_id="debian"
  fi

  ensure_packages ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f "$DOCKER_KEY_FILE" ]]; then
    if curl -fsSL "https://download.docker.com/linux/${repo_id}/gpg" | gpg --dearmor > "$DOCKER_KEY_FILE"; then
      chmod a+r "$DOCKER_KEY_FILE"
      repo_configured=1
    else
      log_warn "Failed to download Docker signing key; using distribution packages"
      rm -f "$DOCKER_KEY_FILE"
    fi
  else
    repo_configured=1
  fi

  if [[ $repo_configured -eq 1 ]]; then
    local docker_suite=$OS_CODENAME
    if ! curl -fsI "https://download.docker.com/linux/${repo_id}/dists/${docker_suite}/Release" >/dev/null 2>&1; then
      if [[ $docker_suite != "bookworm" ]]; then
        log_warn "Docker repo for $docker_suite unavailable; falling back to bookworm"
        docker_suite=bookworm
      fi
    fi
    cat <<EOF > "$DOCKER_LIST_FILE"
deb [arch=$arch signed-by=$DOCKER_KEY_FILE] https://download.docker.com/linux/${repo_id} $docker_suite stable
EOF
    chmod 644 "$DOCKER_LIST_FILE"
  fi

  APT_UPDATED=0
  apt_update_once || true

  local installed=0
  if [[ $repo_configured -eq 1 ]]; then
    if DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
      installed=1
    else
      log_warn "Docker CE packages unavailable from upstream repo"
    fi
  fi

  if [[ $installed -eq 0 ]]; then
    # shellcheck disable=SC2034  # reset to force a fresh apt_update_once
    APT_UPDATED=0
    apt_update_once || true
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-plugin; then
      log_error "Failed to install Docker packages"
      return 1
    fi
  fi

  systemctl enable --now docker >/dev/null 2>&1 || log_warn "Unable to enable docker service"
  if command -v usermod >/dev/null 2>&1; then
    local target_user=${SUDO_USER:-}
    if [[ -n $target_user && $target_user != "root" ]]; then
      usermod -aG docker "$target_user" 2>/dev/null || log_warn "Could not add $target_user to docker group"
    fi
  fi

  # Sub-option: --docker-buildx-multiarch installs qemu-user-static +
  # binfmt-support so buildx can target arm/amd64/riscv64 images.
  if [[ ${DOCKER_BUILDX_MULTIARCH:-0} -eq 1 ]]; then
    ensure_packages qemu-user-static binfmt-support
    if command -v docker >/dev/null 2>&1; then
      docker run --rm --privileged tonistiigi/binfmt --install all >/dev/null 2>&1 \
        || log_warn "Unable to seed binfmt handlers via tonistiigi/binfmt"
    fi
    log_info "docker: qemu-user-static + binfmt installed for multi-arch buildx"
    write_json_field "$CONFIG_OPTIMISER_STATE" "docker.buildx_multiarch" "enabled"
  fi

  # Sub-option: --docker-cgroupv2 appends the cmdline.txt flag that tells
  # systemd to use the unified cgroup hierarchy.
  if [[ ${DOCKER_CGROUPV2:-0} -eq 1 ]]; then
    if [[ -f "$CMDLINE_FILE" ]]; then
      backup_file "$CMDLINE_FILE"
      local rc=0
      cmdline_ensure_token "systemd.unified_cgroup_hierarchy=1" "$CMDLINE_FILE" || rc=$?
      case $rc in
        0)
          log_info "docker: cgroup v2 enabled in $CMDLINE_FILE (active after reboot)"
          pi_mark_reboot_required "docker:cgroupv2"
          ;;
        1) log_info "docker: cgroup v2 already enabled" ;;
        *) log_warn "docker: failed to update $CMDLINE_FILE for cgroup v2" ;;
      esac
      write_json_field "$CONFIG_OPTIMISER_STATE" "docker.cgroup_v2" "enabled"
    else
      log_warn "cmdline.txt not found; cannot enable cgroup v2"
    fi
  fi
}
