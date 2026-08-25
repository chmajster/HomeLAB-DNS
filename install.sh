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
INSTALL_LOG="/var/log/chrislab-dns-install.log"

CONFIG_JSON=""
RESULT_JSON=""
SILENT=false
APP_HOST="127.0.0.1"
APP_PORT="8080"
BIND_CONFIG="/etc/bind/named.conf"
BIND_LOCAL_CONFIG="/etc/bind/named.conf.local"
BIND_MANAGED_CONFIG="/etc/bind/named.conf.chrislab"
BIND_ZONE_DIR="/etc/bind/zones"
ALLOWED_BIND_READ_ROOTS="/etc/bind,/var/lib/bind,/var/cache/bind"
SESSION_SECURE="false"
SESSION_SAMESITE="lax"
SESSION_MAX_AGE="28800"
AUTO_BACKUP="true"
TRUSTED_HOSTS="*"
LOG_LEVEL="INFO"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD=""
ADMIN_PASSWORD_FILE=""
SYNC_EXISTING="true"
REMOVE_DEFAULT_NGINX_SITE="true"
ADMIN_SECRET_TEMP=""

usage() {
  cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Options:
  --config FILE, --json FILE   Load installation settings from JSON.
  --silent                     Unattended/minimal-output installation.
  --result-json FILE           Write machine-readable installation result (mode 0600).
  -h, --help                   Show this help.

Examples:
  sudo ./install.sh --config config/install.example.json
  sudo ./install.sh --config /root/dns-install.json --silent --result-json /root/dns-result.json
EOF
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

log() {
  if [[ "$SILENT" != true ]]; then
    echo "$*"
  fi
}

run_logged() {
  if [[ "$SILENT" == true ]]; then
    "$@" >>"$INSTALL_LOG" 2>&1
  else
    "$@"
  fi
}

cleanup() {
  if [[ -n "$ADMIN_SECRET_TEMP" ]]; then
    rm -f "$ADMIN_SECRET_TEMP"
  fi
}
trap cleanup EXIT

on_error() {
  local code=$?
  echo "ChrisLab-DNS installation failed (exit $code)." >&2
  if [[ "$SILENT" == true && -f "$INSTALL_LOG" ]]; then
    echo "Last installer log lines:" >&2
    tail -n 40 "$INSTALL_LOG" >&2 || true
  fi
  exit "$code"
}
trap on_error ERR

while (($#)); do
  case "$1" in
    --config|--json)
      (($# >= 2)) || fail "$1 requires a file path"
      CONFIG_JSON="$2"
      shift 2
      ;;
    --silent|--non-interactive)
      SILENT=true
      shift
      ;;
    --result-json)
      (($# >= 2)) || fail "--result-json requires a file path"
      RESULT_JSON="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

if [[ -n "$CONFIG_JSON" && ! -r "$CONFIG_JSON" ]]; then
  fail "JSON configuration is not readable: $CONFIG_JSON"
fi
if [[ -n "$RESULT_JSON" && "$RESULT_JSON" != /* ]]; then
  fail "--result-json must use an absolute path"
fi

if [[ ${EUID} -ne 0 ]]; then
  args=()
  [[ -n "$CONFIG_JSON" ]] && args+=(--config "$CONFIG_JSON")
  [[ "$SILENT" == true ]] && args+=(--silent)
  [[ -n "$RESULT_JSON" ]] && args+=(--result-json "$RESULT_JSON")
  exec sudo -E "$0" "${args[@]}"
fi

install -o root -g root -m 0600 /dev/null "$INSTALL_LOG"

if [[ ! -r /etc/os-release ]]; then
  fail "Unsupported system: /etc/os-release is missing"
fi
# shellcheck disable=SC1091
source /etc/os-release
case "${ID}:${VERSION_ID}" in
  ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
  *) fail "Unsupported distribution: ${ID} ${VERSION_ID}. Supported: Ubuntu 24.04/26.04, Debian 12/13." ;;
esac

export DEBIAN_FRONTEND=noninteractive
if [[ "$SILENT" == true ]]; then
  run_logged apt-get -qq update
  run_logged apt-get -qq install -y bind9 bind9-utils dnsutils python3 python3-venv python3-pip nginx sudo rsync ca-certificates curl
else
  apt-get update
  apt-get install -y bind9 bind9-utils dnsutils python3 python3-venv python3-pip nginx sudo rsync ca-certificates curl
fi

apply_config_pair() {
  local key="$1" value="$2"
  case "$key" in
    APP_HOST) APP_HOST="$value" ;;
    APP_PORT) APP_PORT="$value" ;;
    DATA_DIR) DATA_DIR="$value" ;;
    BIND_CONFIG) BIND_CONFIG="$value" ;;
    BIND_LOCAL_CONFIG) BIND_LOCAL_CONFIG="$value" ;;
    BIND_MANAGED_CONFIG) BIND_MANAGED_CONFIG="$value" ;;
    BIND_ZONE_DIR) BIND_ZONE_DIR="$value" ;;
    ALLOWED_BIND_READ_ROOTS) ALLOWED_BIND_READ_ROOTS="$value" ;;
    SESSION_SECURE) SESSION_SECURE="$value" ;;
    SESSION_SAMESITE) SESSION_SAMESITE="$value" ;;
    SESSION_MAX_AGE) SESSION_MAX_AGE="$value" ;;
    AUTO_BACKUP) AUTO_BACKUP="$value" ;;
    TRUSTED_HOSTS) TRUSTED_HOSTS="$value" ;;
    LOG_LEVEL) LOG_LEVEL="$value" ;;
    ADMIN_USERNAME) ADMIN_USERNAME="$value" ;;
    ADMIN_PASSWORD) ADMIN_PASSWORD="$value" ;;
    ADMIN_PASSWORD_FILE) ADMIN_PASSWORD_FILE="$value" ;;
    SYNC_EXISTING) SYNC_EXISTING="$value" ;;
    REMOVE_DEFAULT_NGINX_SITE) REMOVE_DEFAULT_NGINX_SITE="$value" ;;
    *) fail "Internal error: unsupported normalized JSON option $key" ;;
  esac
}

if [[ -n "$CONFIG_JSON" ]]; then
  python3 "$SOURCE_DIR/scripts/install_config.py" "$CONFIG_JSON" --format json >/dev/null
  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    apply_config_pair "$key" "$value"
  done < <(python3 "$SOURCE_DIR/scripts/install_config.py" "$CONFIG_JSON")
  log "Validated installation JSON: $CONFIG_JSON"
fi

read_existing_env() {
  local key="$1" fallback="$2" value
  value="$(awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
  printf '%s' "${value:-$fallback}"
}

if [[ -f "$ENV_FILE" ]]; then
  # Preserve active installation settings on repeated runs. JSON is for provisioning a new install;
  # changing paths of an existing installation requires an explicit migration, not an installer rerun.
  APP_HOST="$(read_existing_env APP_HOST "$APP_HOST")"
  APP_PORT="$(read_existing_env APP_PORT "$APP_PORT")"
  DATA_DIR="$(read_existing_env APP_DATA_DIR "$DATA_DIR")"
  BIND_CONFIG="$(read_existing_env BIND_CONFIG "$BIND_CONFIG")"
  BIND_LOCAL_CONFIG="$(read_existing_env BIND_LOCAL_CONFIG "$BIND_LOCAL_CONFIG")"
  BIND_MANAGED_CONFIG="$(read_existing_env BIND_MANAGED_CONFIG "$BIND_MANAGED_CONFIG")"
  BIND_ZONE_DIR="$(read_existing_env BIND_ZONE_DIR "$BIND_ZONE_DIR")"
  SESSION_SECURE="$(read_existing_env SESSION_SECURE "$SESSION_SECURE")"
  SESSION_SAMESITE="$(read_existing_env SESSION_SAMESITE "$SESSION_SAMESITE")"
  SESSION_MAX_AGE="$(read_existing_env SESSION_MAX_AGE "$SESSION_MAX_AGE")"
  AUTO_BACKUP="$(read_existing_env AUTO_BACKUP "$AUTO_BACKUP")"
  TRUSTED_HOSTS="$(read_existing_env TRUSTED_HOSTS "$TRUSTED_HOSTS")"
  LOG_LEVEL="$(read_existing_env LOG_LEVEL "$LOG_LEVEL")"
  log "Existing environment detected; runtime paths/settings were preserved."
fi

BACKUP_DIR="$DATA_DIR/backups"
STAGING_DIR="$DATA_DIR/staging"
resolved_data_dir="$(realpath -m "$DATA_DIR")"
case "$resolved_data_dir" in
  /var/lib/*|/srv/*) ;;
  *) fail "APP_DATA_DIR must resolve below /var/lib or /srv" ;;
esac
[[ ! -L "$DATA_DIR" ]] || fail "APP_DATA_DIR must not be a symbolic link"

if ! getent passwd "$APP_USER" >/dev/null; then
  useradd --system --user-group --home-dir "$DATA_DIR" --create-home --shell /usr/sbin/nologin "$APP_USER"
fi
if getent group bind >/dev/null; then
  gpasswd -d "$APP_USER" bind >/dev/null 2>&1 || true
fi
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$DATA_DIR" "$BACKUP_DIR" "$STAGING_DIR"
install -d -o root -g root -m 0700 "$HELPER_STATE_DIR"
if [[ ! -f "$BACKUP_SIGNING_KEY" ]]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_hex(32))' > "$BACKUP_SIGNING_KEY"
fi
chown root:root "$BACKUP_SIGNING_KEY"
chmod 0600 "$BACKUP_SIGNING_KEY"
if [[ ! -d "$BIND_ZONE_DIR" ]]; then
  install -d -o root -g bind -m 0750 "$BIND_ZONE_DIR"
fi
install -d -o root -g root -m 0755 /usr/local/libexec

if [[ -d /etc/bind && ! -f "$DATA_DIR/.preinstall-backup-done" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  tar -C /etc -czf "$BACKUP_DIR/preinstall-bind-${stamp}.tar.gz" bind
  chown "$APP_USER:$APP_GROUP" "$BACKUP_DIR/preinstall-bind-${stamp}.tar.gz"
  chmod 0640 "$BACKUP_DIR/preinstall-bind-${stamp}.tar.gz"
  touch "$DATA_DIR/.preinstall-backup-done"
  chown "$APP_USER:$APP_GROUP" "$DATA_DIR/.preinstall-backup-done"
fi

install -d -o root -g root -m 0755 "$APP_DIR"
if [[ "$SOURCE_DIR" != "$APP_DIR" ]]; then
  rsync -a --delete --exclude '.git/' --exclude '.env' --exclude '.venv/' --exclude 'venv/' "$SOURCE_DIR/" "$APP_DIR/"
fi

ensure_venv_executable() {
  local venv_dir="$APP_DIR/.venv"
  local mount_options=""

  if command -v findmnt >/dev/null 2>&1; then
    mount_options="$(findmnt -T "$APP_DIR" -no OPTIONS 2>/dev/null || true)"
    if [[ ",${mount_options}," == *,noexec,* ]]; then
      fail "$APP_DIR is on a filesystem mounted with noexec. Remount it with exec before installing ChrisLab-DNS."
    fi
  fi

  if [[ -d "$venv_dir" ]]; then
    chmod -R a+rX "$venv_dir" 2>/dev/null || true
    if [[ ! -x "$venv_dir/bin/python" ]] || ! runuser -u "$APP_USER" -- "$venv_dir/bin/python" -c 'import sys' >/dev/null 2>&1; then
      log "Existing Python virtualenv is not executable by $APP_USER; recreating it."
      rm -rf "$venv_dir"
    fi
  fi

  if [[ ! -x "$venv_dir/bin/python" ]]; then
    rm -rf "$venv_dir"
    python3 -m venv "$venv_dir"
  fi

  chmod -R a+rX "$venv_dir"

  if ! runuser -u "$APP_USER" -- "$venv_dir/bin/python" -c 'import sys; print(sys.executable)' >/dev/null 2>&1; then
    {
      echo "Virtualenv execution diagnostics:"
      echo "APP_DIR=$APP_DIR"
      echo "mount_options=${mount_options:-unknown}"
      namei -l "$venv_dir/bin/python" 2>&1 || true
      ls -ld "$APP_DIR" "$venv_dir" "$venv_dir/bin" "$venv_dir/bin/python"* 2>&1 || true
    } >>"$INSTALL_LOG"
    fail "Python virtualenv is not executable by $APP_USER. Check permissions and mount options. Diagnostics: $INSTALL_LOG"
  fi
}

ensure_venv_executable

if [[ "$SILENT" == true ]]; then
  run_logged "$APP_DIR/.venv/bin/pip" install --disable-pip-version-check -q --upgrade pip
  run_logged "$APP_DIR/.venv/bin/pip" install --disable-pip-version-check -q -r "$APP_DIR/backend/requirements.txt"
else
  "$APP_DIR/.venv/bin/pip" install --disable-pip-version-check --upgrade pip
  "$APP_DIR/.venv/bin/pip" install --disable-pip-version-check -r "$APP_DIR/backend/requirements.txt"
fi
chown -R root:root "$APP_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')"
  cat > "$ENV_FILE" <<ENV
APP_HOST=$APP_HOST
APP_PORT=$APP_PORT
APP_DATA_DIR=$DATA_DIR
DATABASE_URL=sqlite:///$DATA_DIR/database.db
BIND_CONFIG=$BIND_CONFIG
BIND_LOCAL_CONFIG=$BIND_LOCAL_CONFIG
BIND_MANAGED_CONFIG=$BIND_MANAGED_CONFIG
BIND_ZONE_DIR=$BIND_ZONE_DIR
BACKUP_DIR=$BACKUP_DIR
STAGING_DIR=$STAGING_DIR
BIND_HELPER=/usr/bin/sudo /usr/local/libexec/bind9-web-manager-helper
SESSION_SECURE=$SESSION_SECURE
SESSION_SAMESITE=$SESSION_SAMESITE
SESSION_MAX_AGE=$SESSION_MAX_AGE
AUTO_BACKUP=$AUTO_BACKUP
TRUSTED_HOSTS=$TRUSTED_HOSTS
LOG_LEVEL=$LOG_LEVEL
SECRET_KEY=$secret
ENV
fi
chown root:"$APP_GROUP" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

install -o root -g root -m 0755 "$APP_DIR/scripts/privileged_helper.py" /usr/local/libexec/bind9-web-manager-helper
cat > "$HELPER_CONF" <<CONF
BIND_ROOT=/etc/bind
BIND_CONFIG=$BIND_CONFIG
BIND_MANAGED_CONFIG=$BIND_MANAGED_CONFIG
BIND_ZONE_DIR=$BIND_ZONE_DIR
BACKUP_DIR=$BACKUP_DIR
STAGING_DIR=$STAGING_DIR
APP_USER=$APP_USER
BACKUP_SIGNING_KEY=$BACKUP_SIGNING_KEY
ALLOWED_BIND_READ_ROOTS=$ALLOWED_BIND_READ_ROOTS
CONF
chown root:root "$HELPER_CONF"
chmod 0600 "$HELPER_CONF"
install -o root -g root -m 0440 "$APP_DIR/config/sudoers" /etc/sudoers.d/bind9-web-manager
visudo -cf /etc/sudoers.d/bind9-web-manager >/dev/null

if [[ ! -f "$BIND_MANAGED_CONFIG" ]]; then
  printf '%s\n' '// Managed by ChrisLab-DNS.' > "$BIND_MANAGED_CONFIG"
fi
chown root:bind "$BIND_MANAGED_CONFIG"
chmod 0640 "$BIND_MANAGED_CONFIG"
include_line="include \"$BIND_MANAGED_CONFIG\";"
if ! grep -Fqx "$include_line" "$BIND_LOCAL_CONFIG"; then
  local_backup="$BACKUP_DIR/named.conf.local.before-chrislab"
  cp -a "$BIND_LOCAL_CONFIG" "$local_backup"
  printf '\n%s\n' "$include_line" >> "$BIND_LOCAL_CONFIG"
  if ! named-checkconf "$BIND_CONFIG"; then
    cp -a "$local_backup" "$BIND_LOCAL_CONFIG"
    fail "BIND include validation failed; original local configuration restored."
  fi
fi

SERVICE_TMP="$(mktemp)"
NGINX_TMP="$(mktemp)"
trap 'rm -f "$SERVICE_TMP" "$NGINX_TMP"; cleanup' EXIT
APP_DIR="$APP_DIR" DATA_DIR="$DATA_DIR" APP_HOST="$APP_HOST" APP_PORT="$APP_PORT" python3 - "$APP_DIR/systemd/bind9-web-manager.service" "$SERVICE_TMP" "$APP_DIR/nginx/bind9-web-manager.conf" "$NGINX_TMP" <<'PY'
import os
import sys
from pathlib import Path

service = Path(sys.argv[1]).read_text(encoding="utf-8")
service = service.replace("WorkingDirectory=/opt/bind9-web-manager", f"WorkingDirectory={os.environ['APP_DIR']}")
service = service.replace("ExecStart=/opt/bind9-web-manager/.venv/bin/python", f"ExecStart={os.environ['APP_DIR']}/.venv/bin/python")
service = service.replace("ReadWritePaths=/var/lib/bind9-web-manager /etc/bind", f"ReadWritePaths={os.environ['DATA_DIR']} /etc/bind")
Path(sys.argv[2]).write_text(service, encoding="utf-8")

nginx = Path(sys.argv[3]).read_text(encoding="utf-8")
nginx = nginx.replace("proxy_pass http://127.0.0.1:8080;", f"proxy_pass http://{os.environ['APP_HOST']}:{os.environ['APP_PORT']};")
Path(sys.argv[4]).write_text(nginx, encoding="utf-8")
PY
install -o root -g root -m 0644 "$SERVICE_TMP" /etc/systemd/system/bind9-web-manager.service
install -o root -g root -m 0644 "$NGINX_TMP" /etc/nginx/sites-available/bind9-web-manager
ln -sfn /etc/nginx/sites-available/bind9-web-manager /etc/nginx/sites-enabled/bind9-web-manager
if [[ "$REMOVE_DEFAULT_NGINX_SITE" == true ]]; then
  rm -f /etc/nginx/sites-enabled/default
fi
run_logged nginx -t

(cd "$APP_DIR" && runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli migrate) >/dev/null

admin_args=(create-admin --username "$ADMIN_USERNAME")
if [[ -n "$ADMIN_PASSWORD" || -n "$ADMIN_PASSWORD_FILE" ]]; then
  ADMIN_SECRET_TEMP="$(mktemp /run/chrislab-dns-admin-password.XXXXXX)"
  if [[ -n "$ADMIN_PASSWORD_FILE" ]]; then
    [[ "$ADMIN_PASSWORD_FILE" == /* ]] || fail "admin.password_file must be absolute"
    [[ -f "$ADMIN_PASSWORD_FILE" && ! -L "$ADMIN_PASSWORD_FILE" ]] || fail "admin.password_file must be a regular non-symlink file"
    [[ -r "$ADMIN_PASSWORD_FILE" ]] || fail "admin.password_file is not readable"
    [[ "$(stat -c %u "$ADMIN_PASSWORD_FILE")" == 0 ]] || fail "admin.password_file must be owned by root"
    admin_password_mode="$(stat -c %a "$ADMIN_PASSWORD_FILE")"
    (( (8#$admin_password_mode & 8#022) == 0 )) || fail "admin.password_file must not be group/world writable"
    [[ "$(stat -c %s "$ADMIN_PASSWORD_FILE")" -le 4096 ]] || fail "admin.password_file is too large"
    cat "$ADMIN_PASSWORD_FILE" > "$ADMIN_SECRET_TEMP"
  else
    printf '%s\n' "$ADMIN_PASSWORD" > "$ADMIN_SECRET_TEMP"
  fi
  chown "$APP_USER:$APP_GROUP" "$ADMIN_SECRET_TEMP"
  chmod 0400 "$ADMIN_SECRET_TEMP"
  admin_args+=(--password-file "$ADMIN_SECRET_TEMP")
fi
admin_output="$(cd "$APP_DIR" && runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli "${admin_args[@]}")"
rm -f "$ADMIN_SECRET_TEMP"
ADMIN_SECRET_TEMP=""

run_logged systemctl daemon-reload
run_logged systemctl enable --now bind9
run_logged named-checkconf "$BIND_CONFIG"
run_logged systemctl enable --now bind9-web-manager
run_logged systemctl enable --now nginx
run_logged systemctl reload nginx

sync_output="SYNC_SKIPPED"
if [[ "$SYNC_EXISTING" == true ]]; then
  sync_output="$(cd "$APP_DIR" && runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli sync-existing 2>&1 || true)"
fi

host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
host_ip="${host_ip:-127.0.0.1}"
install_url="http://${host_ip}/"
one_time_password=""
admin_status="existing"
if [[ "$admin_output" == ONE_TIME_ADMIN_PASSWORD=* ]]; then
  one_time_password="${admin_output#ONE_TIME_ADMIN_PASSWORD=}"
  admin_status="created_generated_password"
elif [[ "$admin_output" == ADMIN_CREATED ]]; then
  admin_status="created_configured_password"
fi

if [[ -n "$RESULT_JSON" ]]; then
  result_parent="$(dirname "$RESULT_JSON")"
  if [[ ! -d "$result_parent" ]]; then
    install -d -o root -g root -m 0700 "$result_parent"
  fi
  [[ ! -L "$result_parent" && "$(stat -c %u "$result_parent")" == 0 ]] || fail "--result-json parent must be a root-owned directory, not a symlink"
  result_parent_mode="$(stat -c %a "$result_parent")"
  (( (8#$result_parent_mode & 8#022) == 0 )) || fail "--result-json parent must not be group/world writable"
  [[ ! -L "$RESULT_JSON" ]] || fail "--result-json target must not be a symbolic link"
  RESULT_URL="$install_url" RESULT_ADMIN_USERNAME="$ADMIN_USERNAME" RESULT_ADMIN_STATUS="$admin_status" RESULT_ADMIN_PASSWORD="$one_time_password" RESULT_SYNC="$sync_output" python3 - "$RESULT_JSON" <<'PY'
import json
import os
import sys
from pathlib import Path

result = {
    "status": "installed",
    "url": os.environ["RESULT_URL"],
    "admin": {
        "username": os.environ["RESULT_ADMIN_USERNAME"],
        "status": os.environ["RESULT_ADMIN_STATUS"],
        "one_time_password": os.environ["RESULT_ADMIN_PASSWORD"] or None,
    },
    "synchronization": os.environ["RESULT_SYNC"],
}
path = Path(sys.argv[1])
path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY
fi

if [[ "$SILENT" == true && -n "$RESULT_JSON" ]]; then
  exit 0
fi

echo "ChrisLab-DNS installed: $install_url"
if [[ -n "$one_time_password" ]]; then
  echo "ONE_TIME_ADMIN_PASSWORD=$one_time_password"
  echo "The administrator password above is shown only once."
elif [[ "$admin_status" == "created_configured_password" ]]; then
  echo "Administrator account '$ADMIN_USERNAME' created using the configured password."
else
  echo "Administrator account '$ADMIN_USERNAME' already exists; existing credentials were preserved."
fi
if [[ "$SYNC_EXISTING" == true ]]; then
  echo "$sync_output"
fi
[[ -n "$RESULT_JSON" ]] && echo "Installation result: $RESULT_JSON"