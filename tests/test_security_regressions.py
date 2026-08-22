from __future__ import annotations

import json
import re
from pathlib import Path

from sqlalchemy import select

from backend.app.models import ApiToken, AuditLog, User
from backend.app.security import create_api_token, hash_password, token_digest


ROOT = Path(__file__).resolve().parents[1]


def test_granular_api_token_cannot_write(client, db):
    user = User(username="limited-admin", password_hash=hash_password("Correct-Horse-44!"), role="administrator", enabled=True)
    db.add(user)
    db.flush()
    raw = create_api_token()
    db.add(
        ApiToken(
            user_id=user.id,
            name="read-zones-only",
            token_hash=token_digest(raw),
            token_prefix=raw[:18],
            permissions=json.dumps(["zones.read"]),
            enabled=True,
        )
    )
    db.commit()
    headers = {"Authorization": f"Bearer {raw}"}
    assert client.get("/api/v1/zones", headers=headers).status_code == 200
    denied = client.post("/api/v1/zones", headers=headers, json={"name": "denied.test"})
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "FORBIDDEN"


def test_session_mutation_requires_csrf(client, db):
    db.add(User(username="webadmin", password_hash=hash_password("Correct-Horse-45!"), role="administrator", enabled=True))
    db.commit()
    page = client.get("/login")
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None
    login = client.post(
        "/login",
        data={"username": "webadmin", "password": "Correct-Horse-45!", "csrf_token": match.group(1)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    denied = client.post("/api/v1/zones", json={"name": "csrf.test"})
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "CSRF_FAILED"


def test_invalid_zone_import_is_rejected(client, auth_headers):
    response = client.post(
        "/api/v1/zones/import/file?zone_name=broken.test",
        headers=auth_headers,
        files={"file": ("db.broken.test", b"www IN A 192.0.2.1\n", "text/plain")},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] in {"ZONE_PARSE_FAILED", "ZONE_SOA_INVALID"}


def test_delete_zone_rejects_stale_version(client, auth_headers):
    zone = client.post("/api/v1/zones", headers=auth_headers, json={"name": "delete-lock.test"}).json()
    record = client.post(
        "/api/v1/zones/delete-lock.test/records",
        headers=auth_headers,
        json={"name": "www", "type": "A", "value": "192.0.2.50", "ttl": 3600, "zone_version": zone["version"]},
    )
    assert record.status_code == 201
    stale = client.delete(
        f"/api/v1/zones/delete-lock.test?zone_version={zone['version']}",
        headers=auth_headers,
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "ZONE_VERSION_CONFLICT"


def test_reverse_zone_rejects_ipv6_and_non_octet_prefix(client, auth_headers):
    ipv6 = client.post("/api/v1/zones/reverse", headers=auth_headers, json={"network": "2001:db8::/64"})
    assert ipv6.status_code == 422
    classless = client.post("/api/v1/zones/reverse", headers=auth_headers, json={"network": "192.0.2.0/25"})
    assert classless.status_code == 422


def test_successful_dns_change_is_audited(client, auth_headers, db):
    response = client.post("/api/v1/zones", headers=auth_headers, json={"name": "audit.test"})
    assert response.status_code == 201
    row = db.scalar(select(AuditLog).where(AuditLog.action == "CREATE_ZONE", AuditLog.zone == "audit.test"))
    assert row is not None
    assert row.result == "SUCCESS"


def test_privileged_configuration_has_no_blanket_sudo_or_bind_group_membership():
    sudoers = (ROOT / "config" / "sudoers").read_text(encoding="utf-8")
    unit = (ROOT / "systemd" / "bind9-web-manager.service").read_text(encoding="utf-8")
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "NOPASSWD: ALL" not in sudoers
    assert "SupplementaryGroups=bind" not in unit
    assert 'usermod -a -G bind "$APP_USER"' not in installer
    assert 'gpasswd -d "$APP_USER" bind' in installer


def test_uninstall_never_recursively_deletes_zone_directory():
    uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    assert "rm -rf /etc/bind/zones" not in uninstall
