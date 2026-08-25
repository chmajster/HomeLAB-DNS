#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_INSTALLER="$SOURCE_DIR/install.sh"
DEFAULT_CONFIG="/root/configs/install_HomeLAB-dns.json"
ORIGINAL_ARGS=("$@")

CONFIG_FILE="$DEFAULT_CONFIG"
CONFIG_EXPLICIT=false
CONFIG_LOADED=false
SILENT=false
RESULT_JSON=""

FORWARD_DNS_SERVER=""
WEB_UI_IP="0.0.0.0"
PUBLIC_PORT="81"
PANEL_LOGIN="admin"
PANEL_PASSWORD="admin"
PANEL_PASSWORD_SOURCE_FILE=""
PANEL_API_TOKEN=""
PANEL_API_TOKEN_SOURCE_FILE=""

CLI_PROVISIONING=false
CLI_FORWARD_DNS_SERVER=""
CLI_FORWARD_DNS_SERVER_SET=false
CLI_WEB_UI_IP=""
CLI_WEB_UI_IP_SET=false
CLI_PUBLIC_PORT=""
CLI_PUBLIC_PORT_SET=false
CLI_PANEL_LOGIN=""
CLI_PANEL_LOGIN_SET=false
CLI_PANEL_PASSWORD=""
CLI_PANEL_PASSWORD_SET=false
CLI_PANEL_PASSWORD_FILE=""
CLI_PANEL_PASSWORD_FILE_SET=false
CLI_PANEL_API_TOKEN=""
CLI_PANEL_API_TOKEN_SET=false
CLI_PANEL_API_TOKEN_FILE=""
CLI_PANEL_API_TOKEN_FILE_SET=false

BASE_CONFIG=""
PASSWORD_FILE=""
TOKEN_FILE=""
NORMALIZED_CONFIG=""
BASE_RESULT_JSON=""

usage() {
  cat <<'EOF'
Usage: sudo ./install_HomeLAB-dns.sh [OPTIONS]

Unattended provisioning example:
  sudo ./install_HomeLAB-dns.sh --silent \
    --web-ui-ip 10.0.0.53 \
    --port 81 \
    --forward-dns-server 1.1.1.1

Defaults:
  panel login:    admin
  panel password: admin
  Web UI IP:      0.0.0.0
  Web UI port:    81

Provisioning options:
  --forward-dns-server IP     Upstream DNS forwarder. Required for provisioning mode.
  --web-ui-ip IP              Nginx Web UI listen address.
  --port PORT                 Public Web UI port.
  --panel-login LOGIN         Local ChrisLab DNS account. Default: admin.
  --panel-password PASSWORD   Local ChrisLab DNS password. Default: admin.
                              No installer length minimum is imposed.
  --panel-password-file FILE  Read the local application password from a file.
  --panel-api-token TOKEN     Optional API token; must start with cldns_.
  --panel-api-token-file FILE Read the optional API token from a file.

General options:
  --config FILE, --json FILE  Load provisioning settings from JSON.
                              Default if present: /root/configs/install_HomeLAB-dns.json
  --silent, --non-interactive Minimal-output installation.
  --result-json FILE          Write machine-readable installation result (0600).
  -h, --help                  Show this help.

Authentication:
  The application starts with its local account database selected. Linux/PAM or
  LDAP can be selected later in Settings -> Authentication. The installer never
  needs to create or change a Linux login account for normal Web UI access.

Security:
  Command-line secrets can be visible in shell history/process listings. For
  automation prefer --panel-password-file and --panel-api-token-file.
EOF
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

log() {
  [[ "$SILENT" == true ]] || echo "$*"
}

need_value() {
  (($# >= 2)) || fail "$1 requires a value"
}

cleanup() {
  [[ -n "$BASE_CONFIG" ]] && rm -f "$BASE_CONFIG"
  [[ -n "$PASSWORD_FILE" ]] && rm -f "$PASSWORD_FILE"
  [[ -n "$TOKEN_FILE" ]] && rm -f "$TOKEN_FILE"
  [[ -n "$NORMALIZED_CONFIG" ]] && rm -f "$NORMALIZED_CONFIG"
  [[ -n "$BASE_RESULT_JSON" ]] && rm -f "$BASE_RESULT_JSON"
  return 0
}
trap cleanup EXIT

while (($#)); do
  case "$1" in
    --config|--json)
      need_value "$@"
      CONFIG_FILE="$2"
      CONFIG_EXPLICIT=true
      shift 2
      ;;
    --silent|--non-interactive)
      SILENT=true
      shift
      ;;
    --result-json)
      need_value "$@"
      RESULT_JSON="$2"
      shift 2
      ;;
    --forward-dns-server)
      need_value "$@"
      CLI_FORWARD_DNS_SERVER="$2"
      CLI_FORWARD_DNS_SERVER_SET=true
      CLI_PROVISIONING=true
      shift 2
      ;;
    --web-ui-ip)
      need_value "$@"
      CLI_WEB_UI_IP="$2"
      CLI_WEB_UI_IP_SET=true
      CLI_PROVISIONING=true
      shift 2
      ;;
    --port|--web-ui-port)
      need_value "$@"
      CLI_PUBLIC_PORT="$2"
      CLI_PUBLIC_PORT_SET=true
      CLI_PROVISIONING=true
      shift 2
      ;;
    --panel-login)
      need_value "$@"
      CLI_PANEL_LOGIN="$2"
      CLI_PANEL_LOGIN_SET=true
      CLI_PROVISIONING=true
      shift 2
      ;;
    --panel-password)
      need_value "$@"
      CLI_PANEL_PASSWORD="$2"
      CLI_PANEL_PASSWORD_SET=true
      CLI_PROVISIONING=true
      shift 2
      ;;
    --panel-password-file)
      need_value "$@"
      CLI_PANEL_PASSWORD_FILE="$2"
      CLI_PANEL_PASSWORD_FILE_SET=true
      CLI_PROVISIONING=true
      shift 2
      ;;
    --panel-api-token)
      need_value "$@"
      CLI_PANEL_API_TOKEN="$2"
      CLI_PANEL_API_TOKEN_SET=true
      CLI_PROVISIONING=true
      shift 2
      ;;
    --panel-api-token-file)
      need_value "$@"
      CLI_PANEL_API_TOKEN_FILE="$2"
      CLI_PANEL_API_TOKEN_FILE_SET=true
      CLI_PROVISIONING=true
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

[[ "$CLI_PANEL_PASSWORD_SET" != true || "$CLI_PANEL_PASSWORD_FILE_SET" != true ]] \
  || fail "--panel-password and --panel-password-file are mutually exclusive"
[[ "$CLI_PANEL_API_TOKEN_SET" != true || "$CLI_PANEL_API_TOKEN_FILE_SET" != true ]] \
  || fail "--panel-api-token and --panel-api-token-file are mutually exclusive"

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -E "$0" "${ORIGINAL_ARGS[@]}"
fi

[[ -x "$BASE_INSTALLER" ]] || fail "Base installer is missing or not executable: $BASE_INSTALLER"
[[ -z "$RESULT_JSON" || "$RESULT_JSON" == /* ]] || fail "--result-json must use an absolute path"

validate_config_security() {
  local path="$1" mode owner
  [[ "$path" == /* ]] || fail "Configuration path must be absolute: $path"
  [[ -f "$path" && ! -L "$path" ]] || fail "Configuration must be a regular non-symlink file: $path"
  owner="$(stat -c %u "$path")"
  [[ "$owner" == 0 ]] || fail "Configuration must be owned by root: $path"
  mode="$(stat -c %a "$path")"
  (( (8#$mode & 8#077) == 0 )) || fail "Configuration contains secrets and must have mode 0600 (or stricter): $path"
}

validate_secret_file() {
  local path="$1" label="$2" mode owner
  [[ "$path" == /* ]] || fail "$label must use an absolute path"
  [[ -f "$path" && ! -L "$path" ]] || fail "$label must be a regular non-symlink file"
  [[ -r "$path" ]] || fail "$label is not readable"
  owner="$(stat -c %u "$path")"
  [[ "$owner" == 0 ]] || fail "$label must be owned by root"
  mode="$(stat -c %a "$path")"
  (( (8#$mode & 8#077) == 0 )) || fail "$label must have mode 0600 (or stricter)"
  [[ "$(stat -c %s "$path")" -le 4096 ]] || fail "$label is too large"
}

load_config() {
  local path="$1"
  NORMALIZED_CONFIG="$(mktemp /run/homelab-dns-normalized.XXXXXX)"
  chmod 0600 "$NORMALIZED_CONFIG"

  python3 - "$path" >"$NORMALIZED_CONFIG" <<'PY'
import ipaddress
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"Invalid HomeLAB-DNS installer JSON: {exc}")
if not isinstance(data, dict):
    raise SystemExit("HomeLAB-DNS installer JSON must contain an object")

allowed = {
    "forward_dns_server", "web_ui_ip", "panel_login", "panel_password",
    "panel_password_file", "panel_api_token", "panel_api_token_file", "port",
}
unknown = set(data) - allowed
if unknown:
    raise SystemExit("Unknown installer JSON option(s): " + ", ".join(sorted(unknown)))
if "panel_password" in data and "panel_password_file" in data:
    raise SystemExit("panel_password and panel_password_file are mutually exclusive")
if "panel_api_token" in data and "panel_api_token_file" in data:
    raise SystemExit("panel_api_token and panel_api_token_file are mutually exclusive")

def text(name: str) -> str:
    value = data[name]
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{name} must be a non-empty string")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SystemExit(f"{name} must not contain control characters")
    return value

values: dict[str, str] = {}
if "forward_dns_server" in data:
    value = text("forward_dns_server")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise SystemExit("forward_dns_server must be a valid IPv4 or IPv6 address") from exc
    values["FORWARD_DNS_SERVER"] = value
if "web_ui_ip" in data:
    value = text("web_ui_ip")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise SystemExit("web_ui_ip must be a valid IPv4 or IPv6 address") from exc
    values["WEB_UI_IP"] = value
if "panel_login" in data:
    value = text("panel_login")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
        raise SystemExit("panel_login contains unsupported characters for an application account")
    values["PANEL_LOGIN"] = value
if "panel_password" in data:
    values["PANEL_PASSWORD"] = text("panel_password")
if "panel_password_file" in data:
    value = text("panel_password_file")
    if not Path(value).is_absolute():
        raise SystemExit("panel_password_file must use an absolute path")
    values["PANEL_PASSWORD_SOURCE_FILE"] = value
if "panel_api_token" in data:
    value = text("panel_api_token")
    if not value.startswith("cldns_") or len(value) < 32:
        raise SystemExit("panel_api_token must start with 'cldns_' and contain at least 32 characters")
    values["PANEL_API_TOKEN"] = value
if "panel_api_token_file" in data:
    value = text("panel_api_token_file")
    if not Path(value).is_absolute():
        raise SystemExit("panel_api_token_file must use an absolute path")
    values["PANEL_API_TOKEN_SOURCE_FILE"] = value
if "port" in data:
    value = data["port"]
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise SystemExit("port must be an integer between 1 and 65535")
    values["PUBLIC_PORT"] = str(value)
for key, value in values.items():
    sys.stdout.buffer.write(key.encode() + b"\0" + value.encode() + b"\0")
PY

  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    case "$key" in
      FORWARD_DNS_SERVER) FORWARD_DNS_SERVER="$value" ;;
      WEB_UI_IP) WEB_UI_IP="$value" ;;
      PANEL_LOGIN) PANEL_LOGIN="$value" ;;
      PANEL_PASSWORD) PANEL_PASSWORD="$value"; PANEL_PASSWORD_SOURCE_FILE="" ;;
      PANEL_PASSWORD_SOURCE_FILE) PANEL_PASSWORD_SOURCE_FILE="$value"; PANEL_PASSWORD="" ;;
      PANEL_API_TOKEN) PANEL_API_TOKEN="$value"; PANEL_API_TOKEN_SOURCE_FILE="" ;;
      PANEL_API_TOKEN_SOURCE_FILE) PANEL_API_TOKEN_SOURCE_FILE="$value"; PANEL_API_TOKEN="" ;;
      PUBLIC_PORT) PUBLIC_PORT="$value" ;;
      *) fail "Unexpected normalized configuration key: $key" ;;
    esac
  done < "$NORMALIZED_CONFIG"
  CONFIG_LOADED=true
}

run_base_without_provisioning() {
  local args=()
  [[ "$SILENT" == true ]] && args+=(--silent)
  [[ -n "$RESULT_JSON" ]] && args+=(--result-json "$RESULT_JSON")
  exec "$BASE_INSTALLER" "${args[@]}"
}

if [[ -f "$CONFIG_FILE" ]]; then
  validate_config_security "$CONFIG_FILE"
  load_config "$CONFIG_FILE"
elif [[ "$CONFIG_EXPLICIT" == true ]]; then
  fail "Configuration file does not exist: $CONFIG_FILE"
elif [[ "$CLI_PROVISIONING" != true ]]; then
  run_base_without_provisioning
fi

[[ "$CLI_FORWARD_DNS_SERVER_SET" == true ]] && FORWARD_DNS_SERVER="$CLI_FORWARD_DNS_SERVER"
[[ "$CLI_WEB_UI_IP_SET" == true ]] && WEB_UI_IP="$CLI_WEB_UI_IP"
[[ "$CLI_PUBLIC_PORT_SET" == true ]] && PUBLIC_PORT="$CLI_PUBLIC_PORT"
[[ "$CLI_PANEL_LOGIN_SET" == true ]] && PANEL_LOGIN="$CLI_PANEL_LOGIN"
if [[ "$CLI_PANEL_PASSWORD_SET" == true ]]; then
  PANEL_PASSWORD="$CLI_PANEL_PASSWORD"
  PANEL_PASSWORD_SOURCE_FILE=""
elif [[ "$CLI_PANEL_PASSWORD_FILE_SET" == true ]]; then
  PANEL_PASSWORD=""
  PANEL_PASSWORD_SOURCE_FILE="$CLI_PANEL_PASSWORD_FILE"
fi
if [[ "$CLI_PANEL_API_TOKEN_SET" == true ]]; then
  PANEL_API_TOKEN="$CLI_PANEL_API_TOKEN"
  PANEL_API_TOKEN_SOURCE_FILE=""
elif [[ "$CLI_PANEL_API_TOKEN_FILE_SET" == true ]]; then
  PANEL_API_TOKEN=""
  PANEL_API_TOKEN_SOURCE_FILE="$CLI_PANEL_API_TOKEN_FILE"
fi

if [[ -n "$PANEL_PASSWORD_SOURCE_FILE" ]]; then
  validate_secret_file "$PANEL_PASSWORD_SOURCE_FILE" "panel password file"
  PANEL_PASSWORD="$(<"$PANEL_PASSWORD_SOURCE_FILE")"
fi
if [[ -n "$PANEL_API_TOKEN_SOURCE_FILE" ]]; then
  validate_secret_file "$PANEL_API_TOKEN_SOURCE_FILE" "panel API token file"
  PANEL_API_TOKEN="$(<"$PANEL_API_TOKEN_SOURCE_FILE")"
fi

FORWARD_DNS_SERVER="$FORWARD_DNS_SERVER" WEB_UI_IP="$WEB_UI_IP" PANEL_LOGIN="$PANEL_LOGIN" \
PANEL_PASSWORD="$PANEL_PASSWORD" PANEL_API_TOKEN="$PANEL_API_TOKEN" PUBLIC_PORT="$PUBLIC_PORT" python3 - <<'PY'
import ipaddress
import os
import re

forwarder = os.environ["FORWARD_DNS_SERVER"]
if not forwarder:
    raise SystemExit("Missing provisioning option(s): forward_dns_server")
try:
    ipaddress.ip_address(forwarder)
except ValueError as exc:
    raise SystemExit("forward_dns_server must be a valid IPv4 or IPv6 address") from exc
try:
    ipaddress.ip_address(os.environ["WEB_UI_IP"])
except ValueError as exc:
    raise SystemExit("web_ui_ip must be a valid IPv4 or IPv6 address") from exc
username = os.environ["PANEL_LOGIN"]
password = os.environ["PANEL_PASSWORD"]
if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
    raise SystemExit("panel_login contains unsupported characters for an application account")
if not password:
    raise SystemExit("panel_password must not be empty")
for name, value in (("panel_login", username), ("panel_password", password)):
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SystemExit(f"{name} must not contain control characters")
token = os.environ["PANEL_API_TOKEN"]
if token and (not token.startswith("cldns_") or len(token) < 32):
    raise SystemExit("panel_api_token must start with 'cldns_' and contain at least 32 characters")
port_raw = os.environ["PUBLIC_PORT"]
if not port_raw.isdigit() or not 1 <= int(port_raw) <= 65535:
    raise SystemExit("port must be an integer between 1 and 65535")
PY

BASE_CONFIG="$(mktemp /run/homelab-dns-base-config.XXXXXX.json)"
PASSWORD_FILE="$(mktemp /run/homelab-dns-panel-password.XXXXXX)"
chmod 0600 "$BASE_CONFIG" "$PASSWORD_FILE"
printf '%s\n' "$PANEL_PASSWORD" > "$PASSWORD_FILE"

PANEL_LOGIN="$PANEL_LOGIN" PASSWORD_FILE="$PASSWORD_FILE" python3 - "$BASE_CONFIG" <<'PY'
import json
import os
import sys
from pathlib import Path
config = {
    "app": {"host": "127.0.0.1", "port": 8080},
    "admin": {"username": os.environ["PANEL_LOGIN"], "password_file": os.environ["PASSWORD_FILE"]},
    "installation": {"sync_existing": True, "remove_default_nginx_site": True},
}
Path(sys.argv[1]).write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
PY

base_args=(--config "$BASE_CONFIG")
[[ "$SILENT" == true ]] && base_args+=(--silent)
if [[ "$SILENT" == true || -n "$RESULT_JSON" ]]; then
  BASE_RESULT_JSON="$(mktemp /run/homelab-dns-base-result.XXXXXX.json)"
  rm -f "$BASE_RESULT_JSON"
  base_args+=(--result-json "$BASE_RESULT_JSON")
fi
"$BASE_INSTALLER" "${base_args[@]}"

BIND_OPTIONS="/etc/bind/named.conf.options"
BIND_CONFIG="/etc/bind/named.conf"
[[ -f "$BIND_OPTIONS" && ! -L "$BIND_OPTIONS" ]] || fail "BIND options file is missing or unsafe: $BIND_OPTIONS"
bind_backup="$(mktemp /run/homelab-dns-bind-options.XXXXXX)"
cp -a "$BIND_OPTIONS" "$bind_backup"
if ! FORWARD_DNS_SERVER="$FORWARD_DNS_SERVER" python3 - "$BIND_OPTIONS" <<'PY'
import os
import re
import sys
from pathlib import Path
path = Path(sys.argv[1])
forwarder = os.environ["FORWARD_DNS_SERVER"]
text = path.read_text(encoding="utf-8")
forwarders = re.compile(r"^[ \t]*forwarders\s*\{[^{}]*\}\s*;", re.IGNORECASE | re.DOTALL | re.MULTILINE)
block = f"forwarders {{\n        {forwarder};\n    }};"
if forwarders.search(text):
    text = forwarders.sub(block, text, count=1)
else:
    options = re.search(r"\boptions\s*\{", text, re.IGNORECASE)
    if options is None:
        raise SystemExit("Cannot find the BIND options block")
    text = text[:options.end()] + "\n    " + block + text[options.end():]
path.write_text(text, encoding="utf-8")
PY
then
  cp -a "$bind_backup" "$BIND_OPTIONS"
  rm -f "$bind_backup"
  fail "Failed to configure BIND forwarder"
fi
if ! named-checkconf "$BIND_CONFIG"; then
  cp -a "$bind_backup" "$BIND_OPTIONS"
  rm -f "$bind_backup"
  fail "BIND configuration validation failed; named.conf.options was restored"
fi
rm -f "$bind_backup"
BIND_SERVICE="$(systemctl show -p Id --value bind9.service 2>/dev/null || true)"
[[ -n "$BIND_SERVICE" ]] || BIND_SERVICE="bind9.service"
systemctl reload "$BIND_SERVICE"

NGINX_SITE="/etc/nginx/sites-available/bind9-web-manager"
[[ -f "$NGINX_SITE" && ! -L "$NGINX_SITE" ]] || fail "Nginx site file is missing or unsafe: $NGINX_SITE"
nginx_backup="$(mktemp /run/homelab-dns-nginx.XXXXXX)"
cp -a "$NGINX_SITE" "$nginx_backup"
if ! WEB_UI_IP="$WEB_UI_IP" PUBLIC_PORT="$PUBLIC_PORT" python3 - "$NGINX_SITE" <<'PY'
import ipaddress
import os
import re
import sys
from pathlib import Path
path = Path(sys.argv[1])
ip = ipaddress.ip_address(os.environ["WEB_UI_IP"])
port = int(os.environ["PUBLIC_PORT"])
text = path.read_text(encoding="utf-8")
if ip.version == 4:
    listen_lines = [f"    listen {port} default_server;", f"    listen [::]:{port} default_server;"] if ip.is_unspecified else [f"    listen {ip}:{port} default_server;"]
else:
    listen_lines = [f"    listen [{ip}]:{port} default_server;"]
lines = text.splitlines()
result = []
inserted = False
found = 0
listen_re = re.compile(r"^\s*listen\s+.+\s+default_server;\s*$")
for line in lines:
    if listen_re.match(line):
        found += 1
        if not inserted:
            result.extend(listen_lines)
            inserted = True
        continue
    result.append(line)
if found == 0:
    raise SystemExit("Cannot locate Nginx default_server listen directive")
path.write_text("\n".join(result) + "\n", encoding="utf-8")
PY
then
  cp -a "$nginx_backup" "$NGINX_SITE"
  rm -f "$nginx_backup"
  fail "Failed to configure Nginx Web UI listen address/port"
fi
if ! nginx -t; then
  cp -a "$nginx_backup" "$NGINX_SITE"
  rm -f "$nginx_backup"
  fail "Nginx validation failed; previous site configuration was restored"
fi
rm -f "$nginx_backup"
systemctl reload nginx

if [[ -n "$PANEL_API_TOKEN" ]]; then
  TOKEN_FILE="$(mktemp /run/homelab-dns-api-token.XXXXXX)"
  chmod 0600 "$TOKEN_FILE"
  printf '%s\n' "$PANEL_API_TOKEN" > "$TOKEN_FILE"
  APP_USER="bind9-web-manager"
  APP_DIR="/opt/bind9-web-manager"
  ENV_FILE="/etc/bind9-web-manager.env"
  chown "$APP_USER:$APP_USER" "$TOKEN_FILE"
  chmod 0400 "$TOKEN_FILE"
  (
    cd "$APP_DIR"
    runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" PANEL_LOGIN="$PANEL_LOGIN" TOKEN_FILE="$TOKEN_FILE" "$APP_DIR/.venv/bin/python" - <<'PY'
import json
import os
from pathlib import Path
from sqlalchemy import select
from backend.app.database import SessionLocal, init_db
from backend.app.models import ApiToken, User
from backend.app.permissions import ALL_PERMISSIONS
from backend.app.security import token_digest
username = os.environ["PANEL_LOGIN"]
raw_token = Path(os.environ["TOKEN_FILE"]).read_text(encoding="utf-8").strip()
init_db()
with SessionLocal() as db:
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise SystemExit(f"Panel user does not exist: {username}")
    digest = token_digest(raw_token)
    same_token = db.scalar(select(ApiToken).where(ApiToken.token_hash == digest))
    if same_token is not None and same_token.user_id != user.id:
        raise SystemExit("Configured API token is already assigned to another user")
    row = same_token or db.scalar(select(ApiToken).where(ApiToken.user_id == user.id, ApiToken.name == "install_HomeLAB-dns"))
    if row is None:
        row = ApiToken(user_id=user.id, name="install_HomeLAB-dns", token_hash=digest, token_prefix=raw_token[:18])
        db.add(row)
    row.name = "install_HomeLAB-dns"
    row.token_hash = digest
    row.token_prefix = raw_token[:18]
    row.permissions = json.dumps(sorted(ALL_PERMISSIONS))
    row.enabled = True
    row.expires_at = None
    db.commit()
PY
  )
fi

if [[ "$WEB_UI_IP" == "0.0.0.0" || "$WEB_UI_IP" == "::" ]]; then
  panel_host="$(hostname -I 2>/dev/null | awk '{print $1}')"
  panel_host="${panel_host:-127.0.0.1}"
else
  panel_host="$WEB_UI_IP"
fi
[[ "$panel_host" == *:* ]] && host_for_url="[$panel_host]" || host_for_url="$panel_host"
panel_url="http://${host_for_url}:${PUBLIC_PORT}/"
api_token_configured=false
[[ -n "$PANEL_API_TOKEN" ]] && api_token_configured=true

if [[ -n "$RESULT_JSON" ]]; then
  result_parent="$(dirname "$RESULT_JSON")"
  if [[ ! -d "$result_parent" ]]; then
    install -d -o root -g root -m 0700 "$result_parent"
  fi
  [[ ! -L "$result_parent" && "$(stat -c %u "$result_parent")" == 0 ]] || fail "--result-json parent must be root-owned and not a symlink"
  result_parent_mode="$(stat -c %a "$result_parent")"
  (( (8#$result_parent_mode & 8#022) == 0 )) || fail "--result-json parent must not be group/world writable"
  [[ ! -L "$RESULT_JSON" ]] || fail "--result-json target must not be a symbolic link"
  provisioning_config=""
  [[ "$CONFIG_LOADED" == true ]] && provisioning_config="$CONFIG_FILE"
  RESULT_JSON="$RESULT_JSON" BASE_RESULT_JSON="$BASE_RESULT_JSON" PANEL_URL="$panel_url" WEB_UI_IP="$WEB_UI_IP" \
  PUBLIC_PORT="$PUBLIC_PORT" FORWARD_DNS_SERVER="$FORWARD_DNS_SERVER" PROVISIONING_CONFIG="$provisioning_config" \
  API_TOKEN_CONFIGURED="$api_token_configured" python3 - <<'PY'
import json
import os
from pathlib import Path
base_path_raw = os.environ.get("BASE_RESULT_JSON", "")
base_path = Path(base_path_raw) if base_path_raw else None
result = json.loads(base_path.read_text(encoding="utf-8")) if base_path is not None and base_path.exists() else {"status": "installed"}
result["url"] = os.environ["PANEL_URL"]
result["web_ui_ip"] = os.environ["WEB_UI_IP"]
result["port"] = int(os.environ["PUBLIC_PORT"])
result["forward_dns_server"] = os.environ["FORWARD_DNS_SERVER"]
result["provisioning_config"] = os.environ["PROVISIONING_CONFIG"] or None
result["api_token_configured"] = os.environ["API_TOKEN_CONFIGURED"] == "true"
result["authentication"] = "local"
result["authentication_modes"] = ["local", "pam", "ldap"]
path = Path(os.environ["RESULT_JSON"])
path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
fi

if [[ "$SILENT" == true ]]; then
  exit 0
fi

echo "HomeLAB-DNS installation completed."
echo "Panel URL: $panel_url"
echo "Authentication: local application account (PAM or LDAP can be selected in Settings)"
echo "Web UI listen IP: $WEB_UI_IP"
echo "Web UI port: $PUBLIC_PORT"
echo "Forward DNS server: $FORWARD_DNS_SERVER"
echo "Panel login: $PANEL_LOGIN"
echo "API token configured: $api_token_configured"
if [[ "$PANEL_LOGIN" == "admin" && "$PANEL_PASSWORD" == "admin" ]]; then
  echo "Default credentials: admin / admin"
  echo "Change the default credentials after the first login."
fi
if [[ "$CONFIG_LOADED" == true ]]; then
  echo "Provisioning config: $CONFIG_FILE"
else
  echo "Provisioning source: command line"
fi
[[ -n "$RESULT_JSON" ]] && echo "Installation result: $RESULT_JSON"
