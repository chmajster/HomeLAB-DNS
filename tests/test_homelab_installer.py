from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install_HomeLAB-dns.sh"
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
    assert 'forward_dns_server' in content
    assert 'panel_login' in content
    assert 'panel_password' in content
    assert 'panel_api_token' in content
    assert '"port"' in content


def test_homelab_installer_falls_back_to_normal_installer() -> None:
    content = INSTALLER.read_text(encoding="utf-8")
    assert 'BASE_INSTALLER="$SOURCE_DIR/install.sh"' in content
    assert 'if [[ ! -f "$CONFIG_FILE" ]]; then' in content
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


def test_homelab_example_config_matches_required_schema() -> None:
    data = json.loads(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    assert set(data) == {
        "forward_dns_server",
        "panel_login",
        "panel_password",
        "panel_api_token",
        "port",
    }
    assert data["port"] == 81
    assert data["panel_api_token"].startswith("cldns_")
