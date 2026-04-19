# >>> pi-task
# id: proxy
# version: 1.1.0
# description: Expose a backend via nginx reverse proxy on port 80
# category: network
# default_enabled: 0
# power_sensitive: 0
# flags: --proxy-backend
# gate_var: PROXY_BACKEND
# <<< pi-task

pi_task_register proxy \
  description="Expose a backend via nginx reverse proxy on port 80" \
  category=network \
  version=1.1.0 \
  default_enabled=0 \
  flags="--proxy-backend" \
  gate_var=PROXY_BACKEND

run_proxy() {
  if [[ -z "$PROXY_BACKEND" ]]; then
    log_info "Proxy support not requested; skipping proxy configuration"
    pi_skip_reason "not requested"
    return 2
  fi

  local backend_lower=${PROXY_BACKEND,,}
  local conf=/etc/nginx/sites-available/pi-optimiser-proxy
  local enabled=/etc/nginx/sites-enabled/pi-optimiser-proxy

  if [[ $backend_lower == "off" || $backend_lower == "false" || $backend_lower == "disable" || $backend_lower == "disabled" || $backend_lower == "null" || $backend_lower == "none" ]]; then
    rm -f "$enabled"
    if [[ -f "$conf" ]]; then
      backup_file "$conf"
      rm -f "$conf"
    fi
    if systemctl list-unit-files nginx.service >/dev/null 2>&1; then
      systemctl stop nginx >/dev/null 2>&1 || true
      systemctl disable nginx >/dev/null 2>&1 || log_warn "Unable to disable nginx service"
    fi
    log_info "Proxy configuration removed; nginx disabled"
    write_json_field "$CONFIG_OPTIMISER_STATE" "proxy.backend" "disabled"
    return 0
  fi

  # Interpolating $PROXY_BACKEND into the nginx proxy_pass directive
  # is a directive-injection vector if the value contains ';', '{', or
  # whitespace — nginx would accept trailing directives we never
  # intended. validate_proxy_backend_url rejects anything that isn't
  # a well-formed http(s) URL before we write the config.
  if ! validate_proxy_backend_url "$PROXY_BACKEND"; then
    log_error "--proxy-backend: '$PROXY_BACKEND' is not a valid http(s) URL"
    return 1
  fi

  ensure_packages nginx-light
  mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
  if [[ -f "$conf" ]]; then
    backup_file "$conf"
  fi
  cat <<EOF > "$conf"

map \$http_upgrade \$connection_upgrade {
    default Upgrade;
    ''      close;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location / {
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;

        # WebSocket support (harmless for normal HTTP)
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Sec-WebSocket-Key \$http_sec_websocket_key;
        proxy_set_header Sec-WebSocket-Version \$http_sec_websocket_version;
        proxy_set_header Sec-WebSocket-Protocol \$http_sec_websocket_protocol;
        proxy_set_header Sec-WebSocket-Extensions \$http_sec_websocket_extensions;
        proxy_cache_bypass \$http_upgrade;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_connect_timeout 60;

        proxy_pass $PROXY_BACKEND;
    }
}
EOF
  local default_link=/etc/nginx/sites-enabled/default
  local default_target="" default_backup=""
  if [[ -L "$default_link" ]]; then
    default_target=$(readlink "$default_link")
  elif [[ -f "$default_link" ]]; then
    # Regular file (not a symlink). Stash contents somewhere we can
    # restore from, since we're about to rm the original.
    default_backup="${default_link}.pi-optimiser.$(date +%Y%m%d%H%M%S)"
    cp -a "$default_link" "$default_backup"
    default_target="regular-file:$default_backup"
  fi

  ln -sf "$conf" "$enabled"
  rm -f "$default_link"

  if ! nginx -t >/dev/null 2>&1; then
    log_warn "nginx configuration test failed; reverting proxy site"
    rm -f "$enabled"
    case "$default_target" in
      "")                    ;;  # no prior default
      regular-file:*)
        # Original was a regular file; move the copied content back.
        cp -a "${default_target#regular-file:}" "$default_link" 2>/dev/null || true
        ;;
      *)
        ln -sf "$default_target" "$default_link" 2>/dev/null || true
        ;;
    esac
    pi_skip_reason "nginx config failed validation"
    return 2
  fi

  # nginx accepted the config — the backup copy of the pre-change
  # default is no longer needed. Leave it in place so --undo can
  # restore it if the operator changes their mind later.

  systemctl enable --now nginx >/dev/null 2>&1 || log_warn "Unable to enable nginx service"
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || log_warn "Unable to reload nginx"
  write_json_field "$CONFIG_OPTIMISER_STATE" "proxy.backend" "$PROXY_BACKEND"
  log_info "Proxy configured to $PROXY_BACKEND"
}
