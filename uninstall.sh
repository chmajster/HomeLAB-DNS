#!/usr/bin/env bash
set -Eeuo pipefail
if [[ ${EUID} -ne 0 ]]; then exec sudo -E "$0" "$@"; fi

ask() {
  local prompt="$1" answer
  read -r -p "$prompt [y/N] " answer || true
  [[ "$answer" =~ ^[Yy]$ ]]
}

remove_app=false; remove_db=false; remove_backups=false; remove_bind_config=false; remove_bind=false
if ask "Remove ChrisLab-DNS application and service?"; then remove_app=true; fi
if ask "Remove ChrisLab-DNS database?"; then remove_db=true; fi
if ask "Remove ChrisLab-DNS backups?"; then remove_backups=true; fi
if ask "Remove ChrisLab-DNS managed BIND configuration and managed zone files?"; then remove_bind_config=true; fi
if ask "Uninstall the BIND9 packages themselves?"; then remove_bind=true; fi

if $remove_app; then
  systemctl disable --now bind9-web-manager 2>/dev/null || true
  rm -f /etc/systemd/system/bind9-web-manager.service /etc/nginx/sites-enabled/bind9-web-manager /etc/nginx/sites-available/bind9-web-manager
  rm -f /etc/sudoers.d/bind9-web-manager /usr/local/libexec/bind9-web-manager-helper /etc/bind9-web-manager-helper.conf
  rm -rf /opt/bind9-web-manager
  systemctl daemon-reload
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
fi
if $remove_db; then rm -f /var/lib/bind9-web-manager/database.db /var/lib/bind9-web-manager/database.db-*; fi
if $remove_backups; then rm -rf /var/lib/bind9-web-manager/backups; fi
if $remove_bind_config; then
  if [[ -f /etc/bind/named.conf.local ]]; then
    sed -i '\|^include "/etc/bind/named.conf.chrislab";$|d' /etc/bind/named.conf.local
  fi
  rm -f /etc/bind/named.conf.chrislab
  # Zone files are intentionally preserved. Removing the panel must never erase DNS data implicitly.
  named-checkconf /etc/bind/named.conf
  systemctl reload bind9 2>/dev/null || systemctl reload named 2>/dev/null || true
fi
if $remove_bind; then
  apt-get remove --purge -y bind9 bind9-utils dnsutils
fi
if $remove_app && $remove_backups; then rm -rf /var/lib/bind9-web-manager-helper; fi
if $remove_app && $remove_db && $remove_backups; then
  rm -f /etc/bind9-web-manager.env
  userdel bind9-web-manager 2>/dev/null || true
  rm -rf /var/lib/bind9-web-manager
fi

echo "Uninstall choices applied. DNS zones were preserved unless managed BIND configuration removal was explicitly confirmed."
