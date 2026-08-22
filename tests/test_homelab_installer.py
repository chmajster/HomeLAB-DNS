from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install_HomeLAB-dns.sh"


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
    assert "mode 0600" in content
    assert "chmod(0o600)" in content
    assert "chown root:root" in content
