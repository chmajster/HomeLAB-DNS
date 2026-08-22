from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import privileged_helper as helper


def helper_config(tmp_path: Path) -> tuple[dict[str, str], Path, Path, Path]:
    bind = tmp_path / "bind"
    zones = bind / "zones"
    backups = tmp_path / "backups"
    staging = tmp_path / "staging"
    for path in (zones, backups, staging):
        path.mkdir(parents=True, exist_ok=True)
    (bind / "named.conf").write_text('include "named.conf.local";\n', encoding="utf-8")
    (bind / "named.conf.local").write_text('', encoding="utf-8")
    (bind / "named.conf.chrislab").write_text('', encoding="utf-8")
    config = {
        "BIND_ROOT": str(bind),
        "BIND_CONFIG": str(bind / "named.conf"),
        "BIND_MANAGED_CONFIG": str(bind / "named.conf.chrislab"),
        "BIND_ZONE_DIR": str(zones),
        "BACKUP_DIR": str(backups),
        "STAGING_DIR": str(staging),
        "APP_USER": "unused-in-test",
        "ALLOWED_BIND_READ_ROOTS": str(bind),
    }
    return config, bind, zones, backups


def test_export_is_signed_and_omits_rndc_key(tmp_path, monkeypatch):
    config, bind, zones, backups = helper_config(tmp_path)
    zone = zones / "db.example.test"
    zone.write_text("zone-data", encoding="utf-8")
    (bind / "rndc.key").write_text("secret-control-key", encoding="utf-8")
    key = b"k" * 32
    monkeypatch.setattr(helper, "load_backup_signing_key", lambda cfg: key)
    monkeypatch.setattr(helper, "app_ids", lambda cfg: (os.getuid(), os.getgid()))
    monkeypatch.setattr(
        helper,
        "declared_zone_files",
        lambda cfg: {zone.resolve(): {"name": "example.test", "type": "primary", "file": str(zone)}},
    )
    work = backups / "backup-test"
    work.mkdir()
    destination = work / "bind.tar.gz"
    helper.cmd_export_bind(SimpleNamespace(dest=str(destination)), config)
    signature = Path(str(destination) + ".sig")
    assert destination.is_file() and signature.is_file()
    assert signature.read_text(encoding="ascii").strip() == helper.file_hmac(destination, key)
    with tarfile.open(destination, "r:gz") as tar:
        names = set(tar.getnames())
    assert "bind/zones/db.example.test" in names
    assert "bind/rndc.key" not in names


def test_tampered_signed_backup_is_rejected_before_restore(tmp_path, monkeypatch):
    config, bind, zones, backups = helper_config(tmp_path)
    key = b"z" * 32
    monkeypatch.setattr(helper, "load_backup_signing_key", lambda cfg: key)
    work = backups / "restore-test"
    work.mkdir()
    archive = work / "bind.tar.gz"
    archive.write_bytes(b"not-a-real-signed-backup")
    Path(str(archive) + ".sig").write_text("0" * 64 + "\n", encoding="ascii")
    with pytest.raises(helper.HelperError, match="signature verification failed"):
        helper.cmd_restore_bind(SimpleNamespace(source=str(archive)), config)


def test_read_zone_only_allows_declared_zone_file(tmp_path, monkeypatch, capsys):
    config, bind, zones, _ = helper_config(tmp_path)
    zone = zones / "db.example.test"
    zone.write_text("safe-zone", encoding="utf-8")
    secret = bind / "rndc.key"
    secret.write_text("must-not-be-readable", encoding="utf-8")
    monkeypatch.setattr(
        helper,
        "discover_zone_entries",
        lambda cfg: [{"name": "example.test", "type": "primary", "file": str(zone)}],
    )
    helper.cmd_read_zone(SimpleNamespace(file=str(zone)), config)
    assert capsys.readouterr().out == "safe-zone"
    with pytest.raises(helper.HelperError, match="not a declared BIND zone file"):
        helper.cmd_read_zone(SimpleNamespace(file=str(secret)), config)
