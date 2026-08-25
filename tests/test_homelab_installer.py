from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install_HomeLAB-dns.sh"
BASE_INSTALLER = ROOT / "install.sh"
EXAMPLE_CONFIG = ROOT / "config" / "install_HomeLAB-dns.example.json"


def test_homelab_installer_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(INSTALLER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_homelab_installer_uses_expected_default_config() -> None:
    content = INSTALLER.read_text(encoding="utf-8")
    assert 'DEFAULT_CONFIG="/root/configs/install_HomeLAB-dns.json"' in content
    assert 'PUBLIC_PORT="81"' in content
    assert 'PANEL_LOGIN="admin"' in content
    assert 'PANEL_PASSWORD="admin"' in content
    assert 'forward_dns_server' in content
    assert 'panel_login' in content
    assert 'panel_password' in content
    assert 'panel_api_token' in content
    assert '"port"' in content


def test_homelab_installer_falls_back_to_normal_installer() -> None:
    content = INSTALLER.read_text(encoding="utf-8")
    assert 'BASE_INSTALLER="$SOURCE_DIR/install.sh"' in content
    assert 'run_base_without_provisioning()' in content
    assert 'if [[ -f "$CONFIG_FILE" ]]; then' in content
    assert 'elif [[ "$CONFIG_EXPLICIT" == true ]]; then' in content
    assert 'elif [[ "$CLI_PROVISIONING" != true ]]; then' in content
    assert 'exec "$BASE_INSTALLER" "${args[@]}"' in content
    assert "create_interactive_config" not in content


def test_homelab_installer_applies_runtime_configuration() -> None:
    content = INSTALLER.read_text(encoding="utf-8")
    assert "/etc/bind/named.conf.options" in content
    assert "named-checkconf" in content
    assert "/etc/nginx/sites-available/bind9-web-manager" in content
    assert "nginx -t" in content
    assert "ApiToken" in content
    assert "token_digest" in content
    assert "ALL_PERMISSIONS" in content


def test_homelab_installer_protects_secret_config() -> None:
    content = INSTALLER.read_text(encoding="utf-8")
    assert "Configuration must be owned by root" in content
    assert "mode 0600" in content
    assert "! -L" in content
    assert "chmod 0600" in content
    assert "path.chmod(0o600)" in content


def test_homelab_installer_uses_local_application_identity() -> None:
    content = INSTALLER.read_text(encoding="utf-8")
    assert '"admin": {"username": os.environ["PANEL_LOGIN"], "password_file": os.environ["PASSWORD_FILE"]}' in content
    assert 'result["authentication"] = "local"' in content
    assert 'result["authentication_modes"] = ["local", "pam", "ldap"]' in content
    assert "local application account" in content
    assert 'getent passwd "$PANEL_LOGIN"' not in content
    assert 'useradd --create-home --shell /bin/bash "$PANEL_LOGIN"' not in content
    assert 'printf \'%s:%s\\n\' "$PANEL_LOGIN" "$PANEL_PASSWORD" | chpasswd' not in content


def test_application_service_is_enabled_for_os_startup() -> None:
    content = BASE_INSTALLER.read_text(encoding="utf-8")
    assert 'systemctl enable --now bind9-web-manager' in content
    service = (ROOT / "systemd" / "bind9-web-manager.service").read_text(encoding="utf-8")
    assert "WantedBy=multi-user.target" in service
    assert "Restart=on-failure" in service


def test_panel_api_token_is_optional() -> None:
    content = INSTALLER.read_text(encoding="utf-8")
    assert 'token = os.environ["PANEL_API_TOKEN"]' in content
    assert 'if token and (not token.startswith("cldns_") or len(token) < 32):' in content
    assert 'if [[ -n "$PANEL_API_TOKEN" ]]; then' in content
    assert 'api_token_configured=false' in content


def test_installer_has_no_panel_password_length_restriction() -> None:
    content = INSTALLER.read_text(encoding="utf-8")
    assert "panel_password must contain at least 12 characters" not in content
    parser = (ROOT / "scripts" / "install_config.py").read_text(encoding="utf-8")
    assert "admin.password must contain at least 12 characters" not in parser


def test_homelab_example_config_matches_required_schema() -> None:
    data = json.loads(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    assert set(data) == {
        "forward_dns_server",
        "web_ui_ip",
        "panel_login",
        "panel_password",
        "port",
    }
    assert data["port"] == 81
    assert "panel_api_token" not in data
