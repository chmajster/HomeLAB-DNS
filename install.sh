#!/usr/bin/env bash
set -Eeuo pipefail

APP_USER="bind9-web-manager"
APP_GROUP="bind9-web-manager"
APP_DIR="/opt/bind9-web-manager"
DATA_DIR="/var/lib/bind9-web-manager"
ENV_FILE="/etc/bind9-web-manager.env"
HELPER_CONF="/etc/bind9-web-manager-helper.conf"
HELPER_STATE_DIR="/var/lib/bind9-web-manager-helper"
BACKUP_SIGNING_KEY="$HELPER_STATE_DIR/backup-signing.key"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -E "$0" "$@"
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Unsupported system: /etc/os-release is missing" >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
case "${ID}:${VERSION_ID}" in
  ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
  *) echo "Unsupported distribution: ${ID} ${VERSION_ID}. Supported: Ubuntu 24.04/26.04, Debian 12/13." >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y bind9 bind9-utils dnsutils python3 python3-venv python3-pip nginx sudo rsync ca-certificates curl

if ! getent passwd "$APP_USER" >/dev/null; then
  useradd --system --user-group --home-dir "$DATA_DIR" --create-home --shell /usr/sbin/nologin "$APP_USER"
fi
if getent group bind >/dev/null; then
  # The web process must not inherit BIND filesystem write privileges.
  gpasswd -d "$APP_USER" bind >/dev/null 2>&1 || true
fi
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$DATA_DIR" "$DATA_DIR/backups" "$DATA_DIR/staging"
install -d -o root -g root -m 0700 "$HELPER_STATE_DIR"
if [[ ! -f "$BACKUP_SIGNING_KEY" ]]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_hex(32))' > "$BACKUP_SIGNING_KEY"
fi
chown root:root "$BACKUP_SIGNING_KEY"
chmod 0600 "$BACKUP_SIGNING_KEY"
if [[ ! -d /etc/bind/zones ]]; then
  install -d -o root -g bind -m 0750 /etc/bind/zones
fi
install -d -o root -g root -m 0755 /usr/local/libexec

if [[ -d /etc/bind && ! -f "$DATA_DIR/.preinstall-backup-done" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  tar -C /etc -czf "$DATA_DIR/backups/preinstall-bind-${stamp}.tar.gz" bind
  chown "$APP_USER:$APP_GROUP" "$DATA_DIR/backups/preinstall-bind-${stamp}.tar.gz"
  chmod 0640 "$DATA_DIR/backups/preinstall-bind-${stamp}.tar.gz"
  touch "$DATA_DIR/.preinstall-backup-done"
  chown "$APP_USER:$APP_GROUP" "$DATA_DIR/.preinstall-backup-done"
fi

install -d -o root -g root -m 0755 "$APP_DIR"
if [[ "$SOURCE_DIR" != "$APP_DIR" ]]; then
  rsync -a --delete --exclude '.git/' --exclude '.env' --exclude '.venv/' --exclude 'venv/' "$SOURCE_DIR/" "$APP_DIR/"
fi
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --disable-pip-version-check --upgrade pip
"$APP_DIR/.venv/bin/pip" install --disable-pip-version-check -r "$APP_DIR/backend/requirements.txt"
chown -R root:root "$APP_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')"
  cat > "$ENV_FILE" <<ENV
APP_HOST=127.0.0.1
APP_PORT=8080
APP_DATA_DIR=$DATA_DIR
DATABASE_URL=sqlite:///$DATA_DIR/database.db
BIND_CONFIG=/etc/bind/named.conf
BIND_LOCAL_CONFIG=/etc/bind/named.conf.local
BIND_MANAGED_CONFIG=/etc/bind/named.conf.chrislab
BIND_ZONE_DIR=/etc/bind/zones
BACKUP_DIR=$DATA_DIR/backups
STAGING_DIR=$DATA_DIR/staging
BIND_HELPER=/usr/bin/sudo /usr/local/libexec/bind9-web-manager-helper
SESSION_SECURE=false
SESSION_SAMESITE=lax
SESSION_MAX_AGE=28800
AUTO_BACKUP=true
TRUSTED_HOSTS=*
LOG_LEVEL=INFO
SECRET_KEY=$secret
ENV
fi
chown root:"$APP_GROUP" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

install -o root -g root -m 0755 "$APP_DIR/scripts/privileged_helper.py" /usr/local/libexec/bind9-web-manager-helper
cat > "$HELPER_CONF" <<CONF
BIND_ROOT=/etc/bind
BIND_CONFIG=/etc/bind/named.conf
BIND_MANAGED_CONFIG=/etc/bind/named.conf.chrislab
BIND_ZONE_DIR=/etc/bind/zones
BACKUP_DIR=$DATA_DIR/backups
STAGING_DIR=$DATA_DIR/staging
APP_USER=$APP_USER
BACKUP_SIGNING_KEY=$BACKUP_SIGNING_KEY
ALLOWED_BIND_READ_ROOTS=/etc/bind,/var/lib/bind,/var/cache/bind
CONF
chown root:root "$HELPER_CONF"
chmod 0600 "$HELPER_CONF"
install -o root -g root -m 0440 "$APP_DIR/config/sudoers" /etc/sudoers.d/bind9-web-manager
visudo -cf /etc/sudoers.d/bind9-web-manager >/dev/null

if [[ ! -f /etc/bind/named.conf.chrislab ]]; then
  printf '%s\n' '// Managed by ChrisLab-DNS.' > /etc/bind/named.conf.chrislab
fi
chown root:bind /etc/bind/named.conf.chrislab
chmod 0640 /etc/bind/named.conf.chrislab
include_line='include "/etc/bind/named.conf.chrislab";'
if ! grep -Fqx "$include_line" /etc/bind/named.conf.local; then
  cp -a /etc/bind/named.conf.local "$DATA_DIR/backups/named.conf.local.before-chrislab"
  printf '\n%s\n' "$include_line" >> /etc/bind/named.conf.local
  if ! named-checkconf /etc/bind/named.conf; then
    cp -a "$DATA_DIR/backups/named.conf.local.before-chrislab" /etc/bind/named.conf.local
    echo "BIND include validation failed; original named.conf.local restored." >&2
    exit 1
  fi
fi

install -o root -g root -m 0644 "$APP_DIR/systemd/bind9-web-manager.service" /etc/systemd/system/bind9-web-manager.service
install -o root -g root -m 0644 "$APP_DIR/nginx/bind9-web-manager.conf" /etc/nginx/sites-available/bind9-web-manager
ln -sfn /etc/nginx/sites-available/bind9-web-manager /etc/nginx/sites-enabled/bind9-web-manager
rm -f /etc/nginx/sites-enabled/default
nginx -t

(cd "$APP_DIR" && runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli migrate)
admin_output="$(cd "$APP_DIR" && runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli create-admin --username admin)"

systemctl daemon-reload
systemctl enable --now bind9
named-checkconf /etc/bind/named.conf
systemctl enable --now bind9-web-manager
systemctl enable --now nginx
systemctl reload nginx

sync_output="$(cd "$APP_DIR" && runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli sync-existing 2>&1 || true)"

host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
host_ip="${host_ip:-127.0.0.1}"
echo "ChrisLab-DNS installed: http://${host_ip}/"
if [[ "$admin_output" == ONE_TIME_ADMIN_PASSWORD=* ]]; then
  echo "${admin_output}"
  echo "The administrator password above is shown only once."
else
  echo "Administrator account already exists; existing credentials were preserved."
fi
echo "$sync_output"
