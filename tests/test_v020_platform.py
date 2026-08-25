from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from backend.app import authentication
from backend.app.authentication import resolve_ldap_role, save_ldap_settings
from backend.app.errors import AppError
from backend.app.models import TsigKey, User, ZoneRevision
from backend.app.schemas import RecordCreate, TsigKeyCreate, ZoneCreate
from backend.app.security import decrypt_secret, encrypt_secret, hash_password, totp_code, verify_totp
from backend.app.services.platform import DnsPlatformService
from backend.app.services.zones import ZoneService


def test_totp_code_verification_is_time_windowed() -> None:
    secret = "JBSWY3DPEHPK3PXP"
    code = totp_code(secret, timestamp=1_700_000_000)
    assert len(code) == 6
    assert verify_totp(secret, code, timestamp=1_700_000_000)
    assert verify_totp(secret, code, timestamp=1_700_000_030)
    assert not verify_totp(secret, "000000", timestamp=1_700_000_000)


def test_tsig_secret_is_encrypted_at_rest(db) -> None:
    row, secret = DnsPlatformService(db).create_tsig_key(TsigKeyCreate(name="transfer-key"))
    stored = db.get(TsigKey, row.id)
    assert stored is not None
    assert stored.secret_encrypted != secret
    assert decrypt_secret(stored.secret_encrypted) == secret


def test_secondary_zone_renders_primaries_and_tsig(db) -> None:
    DnsPlatformService(db).create_tsig_key(TsigKeyCreate(name="secondary-key"))
    service = ZoneService(db)
    zone = service.create(
        ZoneCreate(
            name="secondary.example",
            zone_type="secondary",
            primary_servers=["192.0.2.10", "192.0.2.11"],
            tsig_key_name="secondary-key",
        ),
        "admin",
    )
    text = service._managed_config()
    assert zone.zone_type == "secondary"
    assert 'zone "secondary.example" {' in text
    assert "type secondary;" in text
    assert "primaries {" in text
    assert '192.0.2.10 key "secondary-key";' in text
    assert 'key "secondary-key" {' in text


def test_secondary_zone_requires_primary_server() -> None:
    with pytest.raises(ValueError):
        ZoneCreate(name="secondary.example", zone_type="secondary")


def test_secondary_zone_records_are_read_only(db) -> None:
    service = ZoneService(db)
    zone = service.create(
        ZoneCreate(name="readonly-secondary.example", zone_type="secondary", primary_servers=["192.0.2.20"]),
        "admin",
    )
    with pytest.raises(AppError) as error:
        service.add_record(
            zone,
            RecordCreate(name="www", type="A", value="192.0.2.30", ttl=3600, zone_version=zone.version),
            "admin",
        )
    assert error.value.code == "SECONDARY_ZONE_READ_ONLY"


def test_zone_revision_can_restore_previous_records(db) -> None:
    service = ZoneService(db)
    zone = service.create(ZoneCreate(name="history.example"), "admin")
    initial_version = zone.version
    service.add_record(
        zone,
        RecordCreate(name="www", type="A", value="192.0.2.40", ttl=3600, zone_version=zone.version),
        "admin",
    )
    revisions = service.list_revisions(zone.name)
    initial = next(item for item in revisions if item.reason == "CREATE_ZONE")
    current_version = zone.version
    restored = service.restore_revision(zone, initial, current_version, "admin")
    assert restored.version > current_version
    assert restored.version > initial_version
    assert all(record.name != "www" for record in restored.records)
    assert db.scalar(select(ZoneRevision.id).where(ZoneRevision.zone_name == zone.name)) is not None


class _MemberOf:
    values = ["cn=dns-operators,ou=groups,dc=example,dc=local"]


class _Entry:
    entry_dn = "uid=chris,ou=people,dc=example,dc=local"
    memberOf = _MemberOf()


class _Connection:
    def unbind(self) -> None:
        return None


def test_ldap_group_maps_to_operator(db, monkeypatch) -> None:
    save_ldap_settings(
        db,
        enabled=True,
        url="ldap://127.0.0.1:389",
        start_tls=False,
        verify_tls=False,
        base_dn="dc=example,dc=local",
        bind_dn="",
        bind_password=None,
        clear_bind_password=False,
        user_filter="(&(objectClass=person)(uid={username}))",
        default_role="read_only",
        operator_group_dn="cn=dns-operators,ou=groups,dc=example,dc=local",
    )
    monkeypatch.setattr(authentication, "_search_ldap_user", lambda settings, username, attributes: (_Connection(), _Entry()))
    assert resolve_ldap_role(db, "chris") == "operator"


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def test_web_login_requires_totp_when_enabled(client, db) -> None:
    secret = "JBSWY3DPEHPK3PXP"
    user = User(
        username="twofa-admin",
        password_hash=hash_password("admin"),
        role="administrator",
        enabled=True,
        totp_secret_encrypted=encrypt_secret(secret),
        totp_enabled=True,
    )
    db.add(user)
    db.commit()

    login_page = client.get("/login")
    response = client.post(
        "/login",
        data={"csrf_token": _csrf(login_page.text), "username": "twofa-admin", "password": "admin"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    protected = client.get("/", follow_redirects=False)
    assert protected.status_code == 303
    assert protected.headers["location"] == "/login/totp"

    challenge = client.get("/login/totp")
    assert challenge.status_code == 200
    verified = client.post(
        "/login/totp",
        data={"csrf_token": _csrf(challenge.text), "code": totp_code(secret)},
        follow_redirects=False,
    )
    assert verified.status_code == 303
    assert client.get("/").status_code == 200
