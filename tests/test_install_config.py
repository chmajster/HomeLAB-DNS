from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from backend.app.cli import read_password_file

ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "scripts" / "install_config.py"


def run_parser(tmp_path: Path, document: object) -> subprocess.CompletedProcess[str]:
    config = tmp_path / "install.json"
    config.write_text(json.dumps(document), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(PARSER), str(config), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_json_install_config_normalizes_values(tmp_path: Path) -> None:
    result = run_parser(
        tmp_path,
        {
            "app": {"host": "127.0.0.1", "port": 8181, "data_dir": "/srv/chrislab-dns"},
            "security": {
                "session_secure": True,
                "session_samesite": "strict",
                "trusted_hosts": ["dns.example.test", "127.0.0.1"],
                "log_level": "warning",
            },
            "admin": {"username": "dns-admin", "password_file": "/root/dns-admin.secret"},
            "installation": {"sync_existing": False, "remove_default_nginx_site": False},
        },
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["APP_PORT"] == "8181"
    assert data["DATA_DIR"] == "/srv/chrislab-dns"
    assert data["SESSION_SECURE"] == "true"
    assert data["TRUSTED_HOSTS"] == "dns.example.test,127.0.0.1"
    assert data["LOG_LEVEL"] == "WARNING"
    assert data["ADMIN_PASSWORD_FILE"] == "/root/dns-admin.secret"
    assert data["SYNC_EXISTING"] == "false"


def test_json_install_config_rejects_unknown_options(tmp_path: Path) -> None:
    result = run_parser(tmp_path, {"installation": {"shell_command": "rm -rf /"}})
    assert result.returncode == 2
    assert "Unknown installation option" in result.stderr


def test_json_install_config_rejects_public_backend_listener(tmp_path: Path) -> None:
    result = run_parser(tmp_path, {"app": {"host": "0.0.0.0"}})
    assert result.returncode == 2
    assert "nginx is the public entry point" in result.stderr


def test_json_install_config_requires_secure_cookie_for_samesite_none(tmp_path: Path) -> None:
    result = run_parser(
        tmp_path,
        {"security": {"session_secure": False, "session_samesite": "none"}},
    )
    assert result.returncode == 2
    assert "requires security.session_secure=true" in result.stderr


def test_json_install_config_rejects_password_and_password_file(tmp_path: Path) -> None:
    result = run_parser(
        tmp_path,
        {"admin": {"password": "LongPassword123!", "password_file": "/root/password"}},
    )
    assert result.returncode == 2
    assert "mutually exclusive" in result.stderr


def test_password_file_reader(tmp_path: Path) -> None:
    password_file = tmp_path / "password"
    password_file.write_text("StrongPassword123!\n", encoding="utf-8")
    assert read_password_file(str(password_file)) == "StrongPassword123!"


def test_password_file_reader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("StrongPassword123!", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="must not be a symlink"):
        read_password_file(str(link))


def test_installer_exposes_json_and_silent_modes() -> None:
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "--config" in install
    assert "--silent" in install
    assert "--result-json" in install
    assert "scripts/install_config.py" in install
    assert "--password-file" in install
