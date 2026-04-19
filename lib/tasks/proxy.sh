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
  local default_target=""
  if [[ -L "$default_link" ]]; then
    default_target=$(readlink "$default_link")
  elif [[ -f "$default_link" ]]; then
    default_target="$default_link"
  fi

  ln -sf "$conf" "$enabled"
  rm -f "$default_link"

  if ! nginx -t >/dev/null 2>&1; then
    log_warn "nginx configuration test failed; reverting proxy site"
    rm -f "$enabled"
    if [[ -n "$default_target" ]]; then
      ln -sf "$default_target" "$default_link" 2>/dev/null || true
    fi
    pi_skip_reason "nginx config failed validation"
    return 2
  fi

  systemctl enable --now nginx >/dev/null 2>&1 || log_warn "Unable to enable nginx service"
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || log_warn "Unable to reload nginx"
  write_json_field "$CONFIG_OPTIMISER_STATE" "proxy.backend" "$PROXY_BACKEND"
  log_info "Proxy configured to $PROXY_BACKEND"
}
