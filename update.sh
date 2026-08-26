#!/usr/bin/env bash
set -Eeuo pipefail
APP_USER="bind9-web-manager"
APP_DIR="/opt/bind9-web-manager"
DATA_DIR="/var/lib/bind9-web-manager"
ENV_FILE="/etc/bind9-web-manager.env"
HELPER_STATE_DIR="/var/lib/bind9-web-manager-helper"
BACKUP_SIGNING_KEY="$HELPER_STATE_DIR/backup-signing.key"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then exec sudo -E "$0" "$@"; fi
if [[ ! -f "$ENV_FILE" || ! -d "$APP_DIR" ]]; then echo "ChrisLab-DNS is not installed." >&2; exit 1; fi

install -d -o root -g root -m 0700 "$HELPER_STATE_DIR"
if [[ ! -f "$BACKUP_SIGNING_KEY" ]]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_hex(32))' > "$BACKUP_SIGNING_KEY"
fi
chown root:root "$BACKUP_SIGNING_KEY"
chmod 0600 "$BACKUP_SIGNING_KEY"
if getent group bind >/dev/null; then
  gpasswd -d "$APP_USER" bind >/dev/null 2>&1 || true
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DATA_DIR/backups"
tar -C /opt -czf "$DATA_DIR/backups/application-before-update-${stamp}.tar.gz" bind9-web-manager
chown "$APP_USER:$APP_USER" "$DATA_DIR/backups/application-before-update-${stamp}.tar.gz"
cd "$APP_DIR"
runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli backup --reason "before application update $stamp"

if [[ -d "$SOURCE_DIR/.git" ]]; then
  git -C "$SOURCE_DIR" pull --ff-only
fi
if [[ "$SOURCE_DIR" != "$APP_DIR" ]]; then
  rsync -a --delete --exclude '.git/' --exclude '.env' --exclude '.venv/' --exclude 'venv/' "$SOURCE_DIR/" "$APP_DIR/"
fi

# Install/upgrade Kea and the restricted DHCP helper. Existing Kea service state
# is preserved; newly installed DHCP services are left disabled/stopped.
bash "$APP_DIR/install_dhcp.sh" --no-restart

"$APP_DIR/.venv/bin/pip" install --disable-pip-version-check -r "$APP_DIR/backend/requirements.txt"
install -o root -g root -m 0755 "$APP_DIR/scripts/privileged_helper.py" /usr/local/libexec/bind9-web-manager-helper
install -o root -g root -m 0644 "$APP_DIR/config/pam-chrislab-dns" /etc/pam.d/chrislab-dns
install -o root -g root -m 0644 "$APP_DIR/systemd/bind9-web-manager.service" /etc/systemd/system/bind9-web-manager.service
install -o root -g root -m 0644 "$APP_DIR/nginx/bind9-web-manager.conf" /etc/nginx/sites-available/bind9-web-manager
cd "$APP_DIR"
runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli migrate
named-checkconf /etc/bind/named.conf
nginx -t
systemctl daemon-reload
systemctl restart bind9-web-manager
systemctl reload nginx
systemctl is-active --quiet bind9-web-manager
systemctl is-active --quiet bind9

echo "Update completed. BIND9 was validated but not restarted. Kea DHCP module was installed/upgraded without enabling a new DHCP service automatically."
