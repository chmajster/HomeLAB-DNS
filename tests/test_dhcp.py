from __future__ import annotations

import pytest

from backend.app.dhcp_schemas import DhcpGlobalUpdate, DhcpPoolCreate, DhcpReservationCreate, DhcpSubnetCreate
from backend.app.errors import AppError
from backend.app.services.dhcp import DhcpService
from backend.app.services.dhcp_runtime import DhcpRuntimeOps


def test_default_dhcp4_draft_is_safe_and_empty(db):
    config = DhcpService(db).load_draft(4)["Dhcp4"]
    assert config["interfaces-config"]["interfaces"] == []
    assert config["subnet4"] == []
    assert config["authoritative"] is True
    assert config["lease-database"]["type"] == "memfile"


def test_default_dhcp6_draft_is_safe_and_empty(db):
    config = DhcpService(db).load_draft(6)["Dhcp6"]
    assert config["interfaces-config"]["interfaces"] == []
    assert config["subnet6"] == []
    assert config["preferred-lifetime"] <= config["valid-lifetime"]


def test_dhcp4_subnet_pool_and_reservation_crud(db):
    service = DhcpService(db)
    service.add_subnet(
        4,
        DhcpSubnetCreate(
            subnet="10.0.10.0/24",
            interface="eth0",
            pool="10.0.10.100 - 10.0.10.200",
            routers=["10.0.10.1"],
            dns_servers=["10.0.10.2"],
            domain_name="lab.local",
        ),
    )
    service.add_pool(4, 1, DhcpPoolCreate(pool="10.0.10.50 - 10.0.10.60"))
    service.add_reservation(
        4,
        1,
        DhcpReservationCreate(identifier_type="hw-address", identifier="00:11:22:33:44:55", address="10.0.10.10", hostname="printer"),
    )
    subnet = service.load_draft(4)["Dhcp4"]["subnet4"][0]
    assert subnet["subnet"] == "10.0.10.0/24"
    assert len(subnet["pools"]) == 2
    assert subnet["reservations"][0]["ip-address"] == "10.0.10.10"
    assert subnet["reservations"][0]["hostname"] == "printer"


def test_dhcp6_reservation_uses_ip_addresses(db):
    service = DhcpService(db)
    service.add_subnet(6, DhcpSubnetCreate(subnet="2001:db8:10::/64", pool="2001:db8:10::1000/120"))
    service.add_reservation(
        6,
        1,
        DhcpReservationCreate(identifier_type="duid", identifier="00:01:00:01:aa:bb", address="2001:db8:10::10", hostname="host6"),
    )
    reservation = service.load_draft(6)["Dhcp6"]["subnet6"][0]["reservations"][0]
    assert reservation["ip-addresses"] == ["2001:db8:10::10"]
    assert reservation["duid"] == "00:01:00:01:aa:bb"


def test_pool_outside_subnet_is_rejected(db):
    service = DhcpService(db)
    service.add_subnet(4, DhcpSubnetCreate(subnet="10.0.10.0/24"))
    with pytest.raises(AppError) as exc:
        service.add_pool(4, 1, DhcpPoolCreate(pool="10.0.20.10 - 10.0.20.20"))
    assert exc.value.code == "INVALID_DHCP_POOL"


def test_unsafe_kea_hook_libraries_are_blocked(db):
    service = DhcpService(db)
    with pytest.raises(AppError) as exc:
        service.save_draft(4, {"Dhcp4": {"interfaces-config": {"interfaces": []}, "subnet4": [], "hooks-libraries": [{"library": "/tmp/evil.so"}]}})
    assert exc.value.code == "UNSAFE_DHCP_CONFIG"


def test_global_settings_update_options(db):
    service = DhcpService(db)
    result = service.set_global(
        4,
        DhcpGlobalUpdate(
            interfaces=["eth0"],
            valid_lifetime=7200,
            renew_timer=1800,
            rebind_timer=3600,
            authoritative=True,
            dns_servers=["10.0.0.2", "10.0.0.3"],
            domain_name="lab.local",
        ),
    )["Dhcp4"]
    assert result["interfaces-config"]["interfaces"] == ["eth0"]
    assert result["valid-lifetime"] == 7200
    options = {row["name"]: row["data"] for row in result["option-data"]}
    assert options["domain-name-servers"] == "10.0.0.2, 10.0.0.3"
    assert options["domain-name"] == "lab.local"


def test_dhcp_api_draft_crud(client, auth_headers):
    response = client.get("/api/v1/dhcp/4/config", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["Dhcp4"]["subnet4"] == []

    response = client.post(
        "/api/v1/dhcp/4/subnets",
        headers=auth_headers,
        json={"subnet": "192.168.50.0/24", "pool": "192.168.50.100 - 192.168.50.200", "routers": ["192.168.50.1"]},
    )
    assert response.status_code == 201
    assert response.json()["Dhcp4"]["subnet4"][0]["id"] == 1

    response = client.post(
        "/api/v1/dhcp/4/subnets/1/reservations",
        headers=auth_headers,
        json={"identifier_type": "hw-address", "identifier": "aa:bb:cc:dd:ee:ff", "address": "192.168.50.10", "hostname": "nas"},
    )
    assert response.status_code == 201
    assert response.json()["Dhcp4"]["subnet4"][0]["reservations"][0]["hostname"] == "nas"


def test_runtime_interfaces_do_not_require_socket_interface_lookup(db, monkeypatch):
    def blocked_socket_lookup():
        raise OSError(97, "Address family not supported by protocol")

    monkeypatch.setattr("backend.app.services.dhcp_runtime.socket.if_nameindex", blocked_socket_lookup)
    interfaces = DhcpRuntimeOps(DhcpService(db)).interfaces()
    assert "lo" not in interfaces
    assert isinstance(interfaces, list)


def test_runtime_restore_rejects_path_traversal(db):
    runtime = DhcpRuntimeOps(DhcpService(db))
    with pytest.raises(AppError) as exc:
        runtime.restore(4, "../kea-dhcp4-20260826T100000Z.json")
    assert exc.value.code == "INVALID_DHCP_BACKUP"


def test_dhcp_backup_api(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        DhcpRuntimeOps,
        "backups",
        lambda self, family: [{"name": f"kea-dhcp{family}-20260826T100000Z.json", "size": 321, "mtime": 1}],
    )
    response = client.get("/api/v1/dhcp/4/backups", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()[0]["name"] == "kea-dhcp4-20260826T100000Z.json"


def test_dhcp_restore_api(client, auth_headers, monkeypatch):
    monkeypatch.setattr(DhcpRuntimeOps, "restore", lambda self, family, name: "RESTORE_OK")
    monkeypatch.setattr(DhcpService, "import_active", lambda self, family: self.load_draft(family))
    response = client.post(
        "/api/v1/dhcp/4/backups/kea-dhcp4-20260826T100000Z.json/restore",
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "restored"
    assert response.json()["backup"] == "kea-dhcp4-20260826T100000Z.json"
