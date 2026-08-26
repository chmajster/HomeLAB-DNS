from __future__ import annotations

from sqlalchemy import select

from backend.app.models import DnsReplicationState
from backend.app.schemas import DnsServerCreate, ZoneCreate
from backend.app.services.platform import DnsPlatformService, compare_dns_serial
from backend.app.services.zones import ZoneService


def test_compare_dns_serial_handles_equal_ahead_lagging_and_wraparound() -> None:
    assert compare_dns_serial(100, 100) == ("in_sync", 0)
    assert compare_dns_serial(101, 100) == ("ahead", 0)
    assert compare_dns_serial(99, 100) == ("lagging", 1)
    assert compare_dns_serial(0, 0xFFFFFFFF) == ("ahead", 0)
    assert compare_dns_serial(0xFFFFFFFF, 0) == ("lagging", 1)


def test_replication_report_persists_remote_health(db, monkeypatch) -> None:
    zone = ZoneService(db).create(ZoneCreate(name="ha.example"), "admin")
    server = DnsPlatformService(db).create_server(
        DnsServerCreate(name="dns02", address="192.0.2.53", role="secondary")
    )

    expected = int(zone.serial)

    def fake_probe(self, address, zone_row, key_name=None, timeout=3.0):
        assert zone_row.name == "ha.example"
        if address == "127.0.0.1":
            return {"status": "ok", "serial": expected, "authoritative": True, "latency_ms": 1, "details": None}
        assert address == server.address
        return {"status": "ok", "serial": expected - 1, "authoritative": True, "latency_ms": 4, "details": None}

    monkeypatch.setattr(DnsPlatformService, "_query_soa_safe", fake_probe)
    report = DnsPlatformService(db).replication_report(zone)

    assert report["expected_serial"] == expected
    assert report["local"]["status"] == "in_sync"
    assert report["servers"][0]["status"] == "lagging"
    assert report["servers"][0]["serial_lag"] == 1

    state = db.scalar(
        select(DnsReplicationState).where(
            DnsReplicationState.server_id == server.id,
            DnsReplicationState.zone_id == zone.id,
        )
    )
    assert state is not None
    assert state.last_status == "lagging"
    assert state.last_serial == expected - 1
    assert state.serial_lag == 1
    assert state.authoritative is True
    assert state.latency_ms == 4


def test_replication_report_secondary_uses_newest_primary_serial(db, monkeypatch) -> None:
    zone = ZoneService(db).create(
        ZoneCreate(
            name="secondary-ha.example",
            zone_type="secondary",
            primary_servers=["192.0.2.10", "192.0.2.11"],
        ),
        "admin",
    )

    probes = {
        "192.0.2.10": 500,
        "192.0.2.11": 503,
        "127.0.0.1": 502,
    }

    def fake_probe(self, address, zone_row, key_name=None, timeout=3.0):
        serial = probes[address]
        return {"status": "ok", "serial": serial, "authoritative": True, "latency_ms": 2, "details": None}

    monkeypatch.setattr(DnsPlatformService, "_query_soa_safe", fake_probe)
    report = DnsPlatformService(db).replication_report(zone)

    assert report["expected_serial"] == 503
    assert report["local"]["status"] == "lagging"
    assert report["local"]["serial_lag"] == 1
    assert [item["serial"] for item in report["configured_primary_sources"]] == [500, 503]


def test_transfer_probe_result_is_persisted(db, monkeypatch) -> None:
    zone = ZoneService(db).create(ZoneCreate(name="transfer-ha.example"), "admin")
    server = DnsPlatformService(db).create_server(
        DnsServerCreate(name="dns03", address="192.0.2.54", role="secondary")
    )

    monkeypatch.setattr(
        DnsPlatformService,
        "_transfer_probe",
        lambda self, server_row, zone_row, transfer_type, timeout=5.0: {
            "allowed": True,
            "rcode": "NOERROR",
            "answer_rrsets": 2,
            "latency_ms": 3,
        },
    )

    result = DnsPlatformService(db).test_transfer(server, zone, "AXFR")
    assert result["status"] == "success"
    assert result["allowed"] is True

    state = db.scalar(
        select(DnsReplicationState).where(
            DnsReplicationState.server_id == server.id,
            DnsReplicationState.zone_id == zone.id,
        )
    )
    assert state is not None
    assert state.last_transfer_test_type == "AXFR"
    assert state.last_transfer_test_status == "success"
    assert state.last_transfer_ok_at is not None


def test_ha_overview_api_is_available(client, auth_headers) -> None:
    response = client.get("/api/v1/ha/replication", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
