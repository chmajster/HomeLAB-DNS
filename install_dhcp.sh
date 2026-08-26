#!/usr/bin/env bash
set -Eeuo pipefail

APP_USER="bind9-web-manager"
APP_GROUP="bind9-web-manager"
APP_DIR="/opt/bind9-web-manager"
DATA_DIR="/var/lib/bind9-web-manager"
ENV_FILE="/etc/bind9-web-manager.env"
DHCP_HELPER_CONF="/etc/chrislab-dhcp-helper.conf"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_ARGS=("$@")
NO_RESTART=false

usage() {
  echo "Usage: bash ./install_dhcp.sh [--no-restart]"
}

while (($#)); do
  case "$1" in
    --no-restart) NO_RESTART=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -E bash "$0" "${ORIGINAL_ARGS[@]}"
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ChrisLab-DNS must be installed before the DHCP module." >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Unsupported system: /etc/os-release missing" >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
case "${ID}:${VERSION_ID}" in
  ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
  *) echo "Unsupported distribution: ${ID} ${VERSION_ID}" >&2; exit 1 ;;
esac

kea4_preexisting=false
kea6_preexisting=false
dpkg-query -W -f='${Status}' kea-dhcp4-server 2>/dev/null | grep -q 'install ok installed' && kea4_preexisting=true || true
dpkg-query -W -f='${Status}' kea-dhcp6-server 2>/dev/null | grep -q 'install ok installed' && kea6_preexisting=true || true

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y kea-dhcp4-server kea-dhcp6-server

# Avoid introducing a rogue DHCP service solely because the package was added.
# Existing Kea installations keep their previous enabled/running state.
if [[ "$kea4_preexisting" == false ]]; then
  systemctl disable --now kea-dhcp4-server >/dev/null 2>&1 || true
fi
if [[ "$kea6_preexisting" == false ]]; then
  systemctl disable --now kea-dhcp6-server >/dev/null 2>&1 || true
fi

if [[ -d "$APP_DIR" && "$SOURCE_DIR" != "$APP_DIR" ]]; then
  install -o root -g root -m 0755 "$SOURCE_DIR/scripts/dhcp_privileged_helper.py" "$APP_DIR/scripts/dhcp_privileged_helper.py"
  install -o root -g root -m 0440 "$SOURCE_DIR/config/sudoers" "$APP_DIR/config/sudoers"
fi
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$SOURCE_DIR/scripts/dhcp_privileged_helper.py" /usr/local/libexec/chrislab-dhcp-helper
install -d -o root -g root -m 0750 "$DATA_DIR/dhcp-backups"
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$DATA_DIR/staging"

cat > "$DHCP_HELPER_CONF" <<CONF
STAGING_DIR=$DATA_DIR/staging
DHCP_BACKUP_DIR=$DATA_DIR/dhcp-backups
KEA_DHCP4_CONFIG=/etc/kea/kea-dhcp4.conf
KEA_DHCP6_CONFIG=/etc/kea/kea-dhcp6.conf
KEA_LEASE_ROOT=/var/lib/kea
APP_USER=$APP_USER
CONF
chown root:root "$DHCP_HELPER_CONF"
chmod 0600 "$DHCP_HELPER_CONF"

install -o root -g root -m 0440 "$SOURCE_DIR/config/sudoers" /etc/sudoers.d/bind9-web-manager
visudo -cf /etc/sudoers.d/bind9-web-manager >/dev/null

if ! grep -q '^DHCP_HELPER=' "$ENV_FILE"; then
  printf '%s\n' 'DHCP_HELPER=/usr/bin/sudo /usr/local/libexec/chrislab-dhcp-helper' >> "$ENV_FILE"
fi
chown root:"$APP_GROUP" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

if [[ "$NO_RESTART" == false ]]; then
  systemctl restart bind9-web-manager
fi

echo "Kea DHCP module installed. DHCPv4/DHCPv6 services were not automatically enabled unless they already existed before installation."
