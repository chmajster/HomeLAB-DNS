from __future__ import annotations

from pathlib import Path

from backend.app.models import Zone
from backend.app.schemas import ZoneCreate
from backend.app.services import dnssec
from backend.app.services.zones import ZoneService


def _create_primary(db, name: str = "dnssec.test") -> Zone:
    return ZoneService(db).create(ZoneCreate(name=name), "tester")


def test_dnssec_status_defaults_to_unsigned(client, db, auth_headers):
    zone = _create_primary(db)
    response = client.get(f"/api/v1/zones/{zone.name}/dnssec", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is False
    assert body["policy"] == "none"
    assert body["signed"] is False
    assert body["ds_sha256"] == []


def test_enable_default_dnssec_policy_writes_runtime_zone(client, db, auth_headers, tmp_path, monkeypatch):
    monkeypatch.setattr(dnssec, "DNSSEC_RUNTIME_DIR", tmp_path)
    zone = _create_primary(db)

    response = client.put(
        f"/api/v1/zones/{zone.name}/dnssec",
        headers=auth_headers,
        json={"version": zone.version, "policy": "default"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True
    assert body["policy"] == "default"
    assert body["version"] == 2

    db.expire_all()
    updated = ZoneService(db).get(zone.name)
    assert updated.dnssec_policy == "default"
    runtime = tmp_path / updated.file_name
    assert runtime.is_file()
    assert f"$ORIGIN {zone.name}." in runtime.read_text(encoding="utf-8")

    managed = Path(ZoneService(db).settings.bind_managed_config).read_text(encoding="utf-8")
    assert f'file "{runtime}";' in managed
    assert "dnssec-policy default;" in managed
    assert "inline-signing yes;" in managed


def test_dnssec_policy_uses_optimistic_lock(client, db, auth_headers, tmp_path, monkeypatch):
    monkeypatch.setattr(dnssec, "DNSSEC_RUNTIME_DIR", tmp_path)
    zone = _create_primary(db, "lock.test")
    response = client.put(
        f"/api/v1/zones/{zone.name}/dnssec",
        headers=auth_headers,
        json={"version": zone.version + 1, "policy": "default"},
    )
    assert response.status_code == 409


def test_dnssec_signing_is_rejected_for_secondary(client, db, auth_headers, tmp_path, monkeypatch):
    monkeypatch.setattr(dnssec, "DNSSEC_RUNTIME_DIR", tmp_path)
    zone = ZoneService(db).create(
        ZoneCreate(name="secondary.test", zone_type="secondary", primary_servers=["192.0.2.53"]),
        "tester",
    )
    response = client.put(
        f"/api/v1/zones/{zone.name}/dnssec",
        headers=auth_headers,
        json={"version": zone.version, "policy": "default"},
    )
    assert response.status_code == 422
