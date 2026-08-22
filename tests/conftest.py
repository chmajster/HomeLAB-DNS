from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

ROOT = Path(tempfile.mkdtemp(prefix="chrislab-dns-pytest-"))
DATA = ROOT / "data"
BIND = ROOT / "bind"
ZONES = BIND / "zones"
for path in (DATA / "backups", DATA / "staging", ZONES):
    path.mkdir(parents=True, exist_ok=True)
(BIND / "named.conf").write_text('include "' + str(BIND / 'named.conf.chrislab') + '";\n', encoding="utf-8")
(BIND / "named.conf.local").write_text('', encoding="utf-8")
(BIND / "named.conf.chrislab").write_text('// test managed config\n', encoding="utf-8")
os.environ.update({
    "TESTING": "true",
    "SESSION_SECURE": "false",
    "SECRET_KEY": "pytest-secret-key",
    "APP_DATA_DIR": str(DATA),
    "DATABASE_URL": f"sqlite:///{DATA / 'database.db'}",
    "BIND_CONFIG": str(BIND / "named.conf"),
    "BIND_LOCAL_CONFIG": str(BIND / "named.conf.local"),
    "BIND_MANAGED_CONFIG": str(BIND / "named.conf.chrislab"),
    "BIND_ZONE_DIR": str(ZONES),
    "BACKUP_DIR": str(DATA / "backups"),
    "STAGING_DIR": str(DATA / "staging"),
    "BIND_HELPER": "/bin/false",
    "AUTO_BACKUP": "false",
})

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.app.database import Base, SessionLocal, engine
from backend.app.main import app
from backend.app.models import ApiToken, User
from backend.app.permissions import ALL_PERMISSIONS
from backend.app.security import create_api_token, hash_password, token_digest
from backend.app.services.zonefile import render_zone, sha256_file
from backend.app.services.zones import ZoneService


@pytest.fixture(autouse=True)
def reset_database(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    for path in ZONES.glob("*"):
        if path.is_file():
            path.unlink()
    (BIND / "named.conf.chrislab").write_text('// test managed config\n', encoding="utf-8")

    def local_apply(self: ZoneService, zone, reason: str, username: str) -> str:
        text = render_zone(zone)
        destination = ZONES / zone.file_name
        temp = DATA / "staging" / (zone.file_name + ".tmp")
        temp.write_text(text, encoding="utf-8")
        os.replace(temp, destination)
        (BIND / "named.conf.chrislab").write_text(self._managed_config(override=zone), encoding="utf-8")
        zone.file_hash = sha256_file(destination)
        zone.validation_status = "valid"
        return text

    def local_remove(self: ZoneService, zone, username: str) -> None:
        destination = ZONES / zone.file_name
        destination.unlink(missing_ok=True)

    monkeypatch.setattr(ZoneService, "_apply", local_apply)
    yield


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def admin_token(db):
    user = User(username="admin", password_hash=hash_password("Correct-Horse-42!"), role="administrator", enabled=True)
    db.add(user); db.flush()
    raw = create_api_token()
    db.add(ApiToken(user_id=user.id, name="tests", token_hash=token_digest(raw), token_prefix=raw[:18], permissions=json.dumps(sorted(ALL_PERMISSIONS)), enabled=True))
    db.commit()
    return raw


@pytest.fixture
def readonly_token(db):
    user = User(username="reader", password_hash=hash_password("Correct-Horse-43!"), role="read_only", enabled=True)
    db.add(user); db.flush()
    raw = create_api_token()
    db.add(ApiToken(user_id=user.id, name="reader", token_hash=token_digest(raw), token_prefix=raw[:18], permissions=json.dumps(sorted(ALL_PERMISSIONS)), enabled=True))
    db.commit()
    return raw


@pytest.fixture
def client():
    with TestClient(app) as value:
        yield value


@pytest.fixture
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
