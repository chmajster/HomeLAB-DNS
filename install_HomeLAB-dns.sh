#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONFIG="/root/configs/install_HomeLAB-dns.json"
CONFIG_FILE="$DEFAULT_CONFIG"
BASE_INSTALLER="$SOURCE_DIR/install.sh"
SILENT=false

FORWARD_DNS_SERVER=""
PANEL_LOGIN=""
PANEL_PASSWORD=""
PANEL_API_TOKEN=""
PUBLIC_PORT="81"

BASE_CONFIG=""
PASSWORD_FILE=""
TOKEN_FILE=""

usage() {
  cat <<'EOF'
Usage: sudo ./install_HomeLAB-dns.sh [OPTIONS]

The installer automatically uses:
  /root/configs/install_HomeLAB-dns.json

If the file does not exist, interactive installation asks for:
  - Forward DNS server
  - DNS Panel login
  - DNS Panel password
  - DNS Panel API token
  - Public panel port (default: 81)

Options:
  --config FILE   Use another HomeLAB-DNS installer JSON file.
  --silent        Pass silent mode to the base installer. Requires an existing JSON file.
  -h, --help      Show this help.
EOF
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

cleanup() {
  [[ -n "$BASE_CONFIG" ]] && rm -f "$BASE_CONFIG"
  [[ -n "$PASSWORD_FILE" ]] && rm -f "$PASSWORD_FILE"
  [[ -n "$TOKEN_FILE" ]] && rm -f "$TOKEN_FILE"
}
trap cleanup EXIT

while (($#)); do
  case "$1" in
    --config)
      (($# >= 2)) || fail "--config requires a file path"
      CONFIG_FILE="$2"
      shift 2
      ;;
    --silent|--non-interactive)
      SILENT=true
      shift
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

if [[ ${EUID} -ne 0 ]]; then
  args=(--config "$CONFIG_FILE")
  [[ "$SILENT" == true ]] && args+=(--silent)
  exec sudo -E "$0" "${args[@]}"
fi

[[ -x "$BASE_INSTALLER" ]] || fail "Base installer is missing or not executable: $BASE_INSTALLER"

validate_config_security() {
  local path="$1" mode owner
  [[ -f "$path" && ! -L "$path" ]] || fail "Configuration must be a regular non-symlink file: $path"
  owner="$(stat -c %u "$path")"
  [[ "$owner" == 0 ]] || fail "Configuration must be owned by root: $path"
  mode="$(stat -c %a "$path")"
  (( (8#$mode & 8#077) == 0 )) || fail "Configuration contains secrets and must have mode 0600 (or stricter): $path"
}

load_config() {
  local path="$1"
  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    case "$key" in
      FORWARD_DNS_SERVER) FORWARD_DNS_SERVER="$value" ;;
      PANEL_LOGIN) PANEL_LOGIN="$value" ;;
      PANEL_PASSWORD) PANEL_PASSWORD="$value" ;;
      PANEL_API_TOKEN) PANEL_API_TOKEN="$value" ;;
      PUBLIC_PORT) PUBLIC_PORT="$value" ;;
      *) fail "Unexpected normalized configuration key: $key" ;;
    esac
  done < <(python3 - "$path" <<'PY'
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

required = {
    "forward_dns_server",
    "panel_login",
    "panel_password",
    "panel_api_token",
    "port",
}
unknown = set(data) - required
missing = required - set(data)
if unknown:
    raise SystemExit("Unknown installer JSON option(s): " + ", ".join(sorted(unknown)))
if missing:
    raise SystemExit("Missing installer JSON option(s): " + ", ".join(sorted(missing)))

forwarder = data["forward_dns_server"]
login = data["panel_login"]
password = data["panel_password"]
token = data["panel_api_token"]
port = data["port"]

for name, value in (
    ("forward_dns_server", forwarder),
    ("panel_login", login),
    ("panel_password", password),
    ("panel_api_token", token),
):
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{name} must be a non-empty string")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SystemExit(f"{name} must not contain control characters")

try:
    ipaddress.ip_address(forwarder)
except ValueError as exc:
    raise SystemExit("forward_dns_server must be a valid IPv4 or IPv6 address") from exc

if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", login):
    raise SystemExit("panel_login contains unsupported characters")
if len(password) < 12:
    raise SystemExit("panel_password must contain at least 12 characters")
if not token.startswith("cldns_") or len(token) < 32:
    raise SystemExit("panel_api_token must start with 'cldns_' and contain at least 32 characters")
if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
    raise SystemExit("port must be an integer between 1 and 65535")

values = {
    "FORWARD_DNS_SERVER": forwarder,
    "PANEL_LOGIN": login,
    "PANEL_PASSWORD": password,
    "PANEL_API_TOKEN": token,
    "PUBLIC_PORT": str(port),
}
for key, value in values.items():
    sys.stdout.buffer.write(key.encode() + b"\0" + value.encode() + b"\0")
PY
  )
}

create_interactive_config() {
  [[ -t 0 ]] || fail "Configuration $CONFIG_FILE does not exist and interactive input is unavailable"

  local value generated_token

  read -r -p "Forward DNS server [1.1.1.1]: " value
  FORWARD_DNS_SERVER="${value:-1.1.1.1}"

  read -r -p "Login do Panelu DNS [admin]: " value
  PANEL_LOGIN="${value:-admin}"

  while :; do
    read -r -s -p "Haslo do Panelu DNS (minimum 12 znakow): " PANEL_PASSWORD
    echo
    [[ ${#PANEL_PASSWORD} -ge 12 ]] && break
    echo "Haslo musi miec co najmniej 12 znakow." >&2
  done

  generated_token="$(python3 -c 'import secrets; print("cldns_" + secrets.token_urlsafe(36))')"
  read -r -p "Token do API PANELU DNS [Enter = wygeneruj automatycznie]: " value
  PANEL_API_TOKEN="${value:-$generated_token}"

  read -r -p "Port dzialania Panelu DNS [81]: " value
  PUBLIC_PORT="${value:-81}"

  python3 - "$FORWARD_DNS_SERVER" "$PANEL_LOGIN" "$PANEL_PASSWORD" "$PANEL_API_TOKEN" "$PUBLIC_PORT" <<'PY'
import ipaddress
import re
import sys

forwarder, login, password, token, port_text = sys.argv[1:]
try:
    ipaddress.ip_address(forwarder)
except ValueError as exc:
    raise SystemExit("Forward DNS server must be a valid IPv4 or IPv6 address") from exc
if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", login):
    raise SystemExit("Panel login contains unsupported characters")
if len(password) < 12:
    raise SystemExit("Panel password must contain at least 12 characters")
if not token.startswith("cldns_") or len(token) < 32:
    raise SystemExit("API token must start with 'cldns_' and contain at least 32 characters")
try:
    port = int(port_text)
except ValueError as exc:
    raise SystemExit("Panel port must be an integer") from exc
if not 1 <= port <= 65535:
    raise SystemExit("Panel port must be between 1 and 65535")
PY

  install -d -o root -g root -m 0700 "$(dirname "$CONFIG_FILE")"
  umask 077
  FORWARD_DNS_SERVER="$FORWARD_DNS_SERVER" PANEL_LOGIN="$PANEL_LOGIN" PANEL_PASSWORD="$PANEL_PASSWORD" PANEL_API_TOKEN="$PANEL_API_TOKEN" PUBLIC_PORT="$PUBLIC_PORT" python3 - "$CONFIG_FILE" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = {
    "forward_dns_server": os.environ["FORWARD_DNS_SERVER"],
    "panel_login": os.environ["PANEL_LOGIN"],
    "panel_password": os.environ["PANEL_PASSWORD"],
    "panel_api_token": os.environ["PANEL_API_TOKEN"],
    "port": int(os.environ["PUBLIC_PORT"]),
}
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
  chown root:root "$CONFIG_FILE"
  echo "Zapisano konfiguracje instalacji: $CONFIG_FILE"
}

if [[ -f "$CONFIG_FILE" ]]; then
  validate_config_security "$CONFIG_FILE"
  load_config "$CONFIG_FILE"
  echo "Uzywam konfiguracji: $CONFIG_FILE"
else
  [[ "$SILENT" != true ]] || fail "Silent installation requires an existing configuration file: $CONFIG_FILE"
  create_interactive_config
  validate_config_security "$CONFIG_FILE"
  load_config "$CONFIG_FILE"
fi

BASE_CONFIG="$(mktemp /run/homelab-dns-base-config.XXXXXX.json)"
PASSWORD_FILE="$(mktemp /run/homelab-dns-panel-password.XXXXXX)"
TOKEN_FILE="$(mktemp /run/homelab-dns-api-token.XXXXXX)"
chmod 0600 "$BASE_CONFIG" "$PASSWORD_FILE" "$TOKEN_FILE"
printf '%s\n' "$PANEL_PASSWORD" > "$PASSWORD_FILE"
printf '%s\n' "$PANEL_API_TOKEN" > "$TOKEN_FILE"

PANEL_LOGIN="$PANEL_LOGIN" PASSWORD_FILE="$PASSWORD_FILE" python3 - "$BASE_CONFIG" <<'PY'
import json
import os
import sys
from pathlib import Path

config = {
    "app": {
        "host": "127.0.0.1",
        "port": 8080,
    },
    "admin": {
        "username": os.environ["PANEL_LOGIN"],
        "password_file": os.environ["PASSWORD_FILE"],
    },
    "installation": {
        "sync_existing": True,
        "remove_default_nginx_site": True,
    },
}
Path(sys.argv[1]).write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
PY

base_args=(--config "$BASE_CONFIG")
[[ "$SILENT" == true ]] && base_args+=(--silent)
"$BASE_INSTALLER" "${base_args[@]}"

BIND_OPTIONS="/etc/bind/named.conf.options"
BIND_CONFIG="/etc/bind/named.conf"
[[ -f "$BIND_OPTIONS" && ! -L "$BIND_OPTIONS" ]] || fail "BIND options file is missing or unsafe: $BIND_OPTIONS"

bind_backup="${BIND_OPTIONS}.before-homelab-dns"
cp -a "$BIND_OPTIONS" "$bind_backup"
if ! FORWARD_DNS_SERVER="$FORWARD_DNS_SERVER" python3 - "$BIND_OPTIONS" <<'PY'
import os
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
forwarder = os.environ["FORWARD_DNS_SERVER"]
text = path.read_text(encoding="utf-8")
forwarders = re.compile(r"\bforwarders\s*\{[^{}]*\}\s*;", re.IGNORECASE | re.DOTALL)
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
  fail "Failed to configure BIND forwarder"
fi

if ! named-checkconf "$BIND_CONFIG"; then
  cp -a "$bind_backup" "$BIND_OPTIONS"
  fail "BIND configuration validation failed; named.conf.options was restored"
fi
rm -f "$bind_backup"
systemctl reload bind9

NGINX_SITE="/etc/nginx/sites-available/bind9-web-manager"
[[ -f "$NGINX_SITE" && ! -L "$NGINX_SITE" ]] || fail "Nginx site file is missing or unsafe: $NGINX_SITE"
nginx_backup="${NGINX_SITE}.before-homelab-dns"
cp -a "$NGINX_SITE" "$nginx_backup"

if ! PUBLIC_PORT="$PUBLIC_PORT" python3 - "$NGINX_SITE" <<'PY'
import os
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
port = os.environ["PUBLIC_PORT"]
text = path.read_text(encoding="utf-8")
text, ipv4_count = re.subn(
    r"(?m)^(\s*listen\s+)\d+(\s+default_server;\s*)$",
    rf"\g<1>{port}\g<2>",
    text,
    count=1,
)
text, ipv6_count = re.subn(
    r"(?m)^(\s*listen\s+\[::\]:)\d+(\s+default_server;\s*)$",
    rf"\g<1>{port}\g<2>",
    text,
    count=1,
)
if ipv4_count != 1 or ipv6_count != 1:
    raise SystemExit("Cannot locate both Nginx listen directives")
path.write_text(text, encoding="utf-8")
PY
then
  cp -a "$nginx_backup" "$NGINX_SITE"
  fail "Failed to configure Nginx public port"
fi

if ! nginx -t; then
  cp -a "$nginx_backup" "$NGINX_SITE"
  nginx -t >/dev/null 2>&1 || true
  fail "Nginx validation failed; previous site configuration was restored"
fi
rm -f "$nginx_backup"
systemctl reload nginx

APP_USER="bind9-web-manager"
APP_GROUP="bind9-web-manager"
APP_DIR="/opt/bind9-web-manager"
ENV_FILE="/etc/bind9-web-manager.env"
chown "$APP_USER:$APP_GROUP" "$TOKEN_FILE"
chmod 0400 "$TOKEN_FILE"

(cd "$APP_DIR" && runuser -u "$APP_USER" -- env \
  ENV_FILE="$ENV_FILE" \
  PANEL_LOGIN="$PANEL_LOGIN" \
  TOKEN_FILE="$TOKEN_FILE" \
  "$APP_DIR/.venv/bin/python" - <<'PY'
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
if not raw_token.startswith("cldns_") or len(raw_token) < 32:
    raise SystemExit("Invalid API token format")

init_db()
with SessionLocal() as db:
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise SystemExit(f"Panel user does not exist: {username}")

    digest = token_digest(raw_token)
    same_token = db.scalar(select(ApiToken).where(ApiToken.token_hash == digest))
    if same_token is not None and same_token.user_id != user.id:
        raise SystemExit("Configured API token is already assigned to another user")

    row = same_token or db.scalar(
        select(ApiToken).where(
            ApiToken.user_id == user.id,
            ApiToken.name == "install_HomeLAB-dns",
        )
    )
    if row is None:
        row = ApiToken(user_id=user.id, name="install_HomeLAB-dns")
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

host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
host_ip="${host_ip:-127.0.0.1}"
if [[ "$host_ip" == *:* ]]; then
  host_for_url="[$host_ip]"
else
  host_for_url="$host_ip"
fi

echo "HomeLAB-DNS installation completed."
echo "Panel URL: http://${host_for_url}:${PUBLIC_PORT}/"
echo "Forward DNS server: $FORWARD_DNS_SERVER"
echo "Panel login: $PANEL_LOGIN"
echo "API token configured from: $CONFIG_FILE"
