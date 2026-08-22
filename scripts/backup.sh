#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="/opt/bind9-web-manager"; ENV_FILE="/etc/bind9-web-manager.env"; APP_USER="bind9-web-manager"
if [[ ${EUID} -ne 0 ]]; then exec sudo -E "$0" "$@"; fi
reason="${1:-manual script backup}"
cd "$APP_DIR"
runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli backup --reason "$reason"
