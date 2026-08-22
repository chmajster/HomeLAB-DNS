#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="/opt/bind9-web-manager"; ENV_FILE="/etc/bind9-web-manager.env"; APP_USER="bind9-web-manager"
if [[ ${EUID} -ne 0 ]]; then exec sudo -E "$0" "$@"; fi
if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+$ ]]; then echo "Usage: $0 BACKUP_ID" >&2; exit 2; fi
cd "$APP_DIR"
runuser -u "$APP_USER" -- env ENV_FILE="$ENV_FILE" "$APP_DIR/.venv/bin/python" -m backend.app.cli restore --id "$1"
