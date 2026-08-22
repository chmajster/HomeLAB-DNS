#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_INSTALLER="$SOURCE_DIR/install.sh"
DEFAULT_CONFIG="/root/configs/install_HomeLAB-dns.json"
CONFIG_FILE="$DEFAULT_CONFIG"
CONFIG_EXPLICIT=false
SILENT=false
RESULT_JSON=""

FORWARD_DNS_SERVER=""
PANEL_LOGIN=""
PANEL_PASSWORD=""
PANEL_API_TOKEN=""
PUBLIC_PORT="81"

BASE_CONFIG=""
PASSWORD_FILE=""
TOKEN_FILE=""
NORMALIZED_CONFIG=""
BASE_RESULT_JSON=""

usage() {
  cat <<'EOF'
Usage: sudo ./install_HomeLAB-dns.sh [OPTIONS]

Provisioning mode automatically looks for:
  /root/configs/install_HomeLAB-dns.json

Expected JSON fields:
  - forward_dns_server
  - panel_login
  - panel_password
  - panel_api_token
  - port

If the default JSON file exists, it is used automatically.
If it does not exist, the normal HomeLAB-DNS installer is executed unchanged.

Options:
  --config FILE       Use another provisioning JSON file. The file must exist.
  --silent            Run unattended/minimal-output installation.
  --result-json FILE  Write machine-readable installation result.
  -h, --help          Show this help.
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
  [[ -n "$NORMALIZED_CONFIG" ]] && rm -f "$NORMALIZED_CONFIG"
  [[ -n "$BASE_RESULT_JSON" ]] && rm -f "$BASE_RESULT_JSON"
}
trap cleanup EXIT

while (($#)); do
  case "$1" in
    --config|--json)
      (($# >= 2)) || fail "$1 requires a file path"
      CONFIG_FILE="$2"
      CONFIG_EXPLICIT=true
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

[[ -x "$BASE_INSTALLER" ]] || fail "Base installer is missing or not executable: $BASE_INSTALLER"

# Exact requested behavior: use the provisioning JSON when it exists;
# otherwise preserve the original HomeLAB-DNS installation flow.
if [[ ! -f "$CONFIG_FILE" ]]; then
  if [[ "$CONFIG_EXPLICIT" == true ]]; then
    fail "Configuration file does not exist: $CONFIG_FILE"
  fi

  args=()
  [[ "$SILENT" == true ]] && args+=(--silent)
  [[ -n "$RESULT_JSON" ]] && args+=(--result-json "$RESULT_JSON")
  exec "$BASE_INSTALLER" "${args[@]}"
fi

if [[ ${EUID} -ne 0 ]]; then
  args=(--config "$CONFIG_FILE")
  [[ "$SILENT" == true ]] && args+=(--silent)
  [[ -n "$RESULT_JSON" ]] && args+=(--result-json "$RESULT_JSON")
  exec sudo -E "$0" "${args[@]}"
fi

validate_config_security() {
  local path="$1" mode owner

  [[ "$path" == /* ]] || fail "Configuration path must be absolute: $path"
  [[ -f "$path" && ! -L "$path" ]] || fail "Configuration must be a regular non-symlink file: $path"
  owner="$(stat -c %u "$path")"
  [[ "$owner" == 0 ]] || fail "Configuration must be owned by root: $path"
  mode="$(stat -c %a "$path")"
  (( (8#$mode & 8#077) == 0 )) || fail "Configuration contains secrets and must have mode 0600 (or stricter): $path"
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

  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    case "$key" in
      FORWARD_DNS_SERVER) FORWARD_DNS_SERVER="$value" ;;
      PANEL_LOGIN) PANEL_LOGIN="$value" ;;
      PANEL_PASSWORD) PANEL_PASSWORD="$value" ;;
      PANEL_API_TOKEN) PANEL_API_TOKEN="$value" ;;
      PUBLIC_PORT) PUBLIC_PORT="$value" ;;
      *) fail "Unexpected normalized configuration key: $key" ;;
    esac
  done < "$NORMALIZED_CONFIG"

  [[ -n "$FORWARD_DNS_SERVER" ]] || fail "forward_dns_server was not loaded"
  [[ -n "$PANEL_LOGIN" ]] || fail "panel_login was not loaded"
  [[ -n "$PANEL_PASSWORD" ]] || fail "panel_password was not loaded"
  [[ -n "$PANEL_API_TOKEN" ]] || fail "panel_api_token was not loaded"
}

validate_config_security "$CONFIG_FILE"
load_config "$CONFIG_FILE"
[[ "$SILENT" == true ]] || echo "Using HomeLAB provisioning configuration: $CONFIG_FILE"

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
if [[ -n "$RESULT_JSON" ]]; then
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
  rm -f "$bind_backup"
  fail "Failed to configure BIND forwarder"
fi

if ! named-checkconf "$BIND_CONFIG"; then
  cp -a "$bind_backup" "$BIND_OPTIONS"
  rm -f "$bind_backup"
  fail "BIND configuration validation failed; named.conf.options was restored"
fi
rm -f "$bind_backup"
systemctl reload bind9

NGINX_SITE="/etc/nginx/sites-available/bind9-web-manager"
[[ -f "$NGINX_SITE" && ! -L "$NGINX_SITE" ]] || fail "Nginx site file is missing or unsafe: $NGINX_SITE"
nginx_backup="$(mktemp /run/homelab-dns-nginx.XXXXXX)"
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
  rm -f "$nginx_backup"
  fail "Failed to configure Nginx public port"
fi

if ! nginx -t; then
  cp -a "$nginx_backup" "$NGINX_SITE"
  rm -f "$nginx_backup"
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

(
  cd "$APP_DIR"
  runuser -u "$APP_USER" -- env \
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
        row = ApiToken(
            user_id=user.id,
            name="install_HomeLAB-dns",
            token_hash=digest,
            token_prefix=raw_token[:18],
        )
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
panel_url="http://${host_for_url}:${PUBLIC_PORT}/"

if [[ -n "$RESULT_JSON" ]]; then
  result_parent="$(dirname "$RESULT_JSON")"
  install -d -o root -g root -m 0700 "$result_parent"
  [[ ! -L "$result_parent" && "$(stat -c %u "$result_parent")" == 0 ]] || fail "--result-json parent must be root-owned and not a symlink"
  [[ ! -L "$RESULT_JSON" ]] || fail "--result-json target must not be a symbolic link"

  RESULT_JSON="$RESULT_JSON" BASE_RESULT_JSON="$BASE_RESULT_JSON" PANEL_URL="$panel_url" FORWARD_DNS_SERVER="$FORWARD_DNS_SERVER" CONFIG_FILE="$CONFIG_FILE" python3 - <<'PY'
import json
import os
from pathlib import Path

base_path = Path(os.environ["BASE_RESULT_JSON"])
result = json.loads(base_path.read_text(encoding="utf-8")) if base_path.exists() else {"status": "installed"}
result["url"] = os.environ["PANEL_URL"]
result["forward_dns_server"] = os.environ["FORWARD_DNS_SERVER"]
result["provisioning_config"] = os.environ["CONFIG_FILE"]
result["api_token_configured"] = True
path = Path(os.environ["RESULT_JSON"])
path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
fi

if [[ "$SILENT" == true && -n "$RESULT_JSON" ]]; then
  exit 0
fi

echo "HomeLAB-DNS installation completed."
echo "Panel URL: $panel_url"
echo "Forward DNS server: $FORWARD_DNS_SERVER"
echo "Panel login: $PANEL_LOGIN"
echo "API token configured from: $CONFIG_FILE"
[[ -n "$RESULT_JSON" ]] && echo "Installation result: $RESULT_JSON"
