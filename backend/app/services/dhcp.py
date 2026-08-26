from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..config import get_settings
from ..dhcp_schemas import DhcpGlobalUpdate, DhcpOptionCreate, DhcpPoolCreate, DhcpReservationCreate, DhcpSubnetCreate
from ..errors import AppError
from ..models import AppState

UNSAFE_KEYS = {"hooks-libraries"}
SERVICE_ACTIONS = {"start", "stop", "restart", "enable", "disable", "enable-start", "disable-stop"}


def _family_root(family: int) -> str:
    if family == 4:
        return "Dhcp4"
    if family == 6:
        return "Dhcp6"
    raise AppError("INVALID_DHCP_FAMILY", "DHCP family must be 4 or 6", 422)


def _subnet_key(family: int) -> str:
    return "subnet4" if family == 4 else "subnet6"


def _default_config(family: int) -> dict[str, Any]:
    root = _family_root(family)
    common: dict[str, Any] = {
        "interfaces-config": {"interfaces": []},
        "lease-database": {
            "type": "memfile",
            "persist": True,
            "name": f"/var/lib/kea/kea-leases{family}.csv",
        },
        "valid-lifetime": 3600,
        "renew-timer": 900,
        "rebind-timer": 1800,
        "option-data": [],
        _subnet_key(family): [],
    }
    if family == 4:
        common["authoritative"] = True
    else:
        common["preferred-lifetime"] = 1800
    return {root: common}


def _reject_unsafe(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in UNSAFE_KEYS:
                raise AppError(
                    "UNSAFE_DHCP_CONFIG",
                    f"Kea setting '{key}' is blocked in Web UI",
                    422,
                    f"Dynamic hook libraries are intentionally blocked at {path}.{key} to prevent service-level code execution.",
                )
            _reject_unsafe(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_unsafe(child, f"{path}[{index}]")


def _validate_document(family: int, document: dict[str, Any]) -> dict[str, Any]:
    root = _family_root(family)
    if set(document) != {root} or not isinstance(document.get(root), dict):
        raise AppError("INVALID_DHCP_CONFIG", f"Configuration must contain exactly one top-level '{root}' object", 422)
    _reject_unsafe(document)
    subnets = document[root].get(_subnet_key(family), [])
    if not isinstance(subnets, list):
        raise AppError("INVALID_DHCP_CONFIG", f"{_subnet_key(family)} must be a list", 422)
    return document


def _normalize_pool(network: Any, value: str) -> str:
    raw = value.strip()
    if not raw:
        raise AppError("INVALID_DHCP_POOL", "Pool cannot be empty", 422)
    if " - " in raw:
        left, right = [item.strip() for item in raw.split(" - ", 1)]
        try:
            first = ipaddress.ip_address(left)
            last = ipaddress.ip_address(right)
        except ValueError as exc:
            raise AppError("INVALID_DHCP_POOL", "Pool contains an invalid IP address", 422, str(exc)) from exc
        if first.version != network.version or last.version != network.version or first not in network or last not in network or int(first) > int(last):
            raise AppError("INVALID_DHCP_POOL", "Pool range must stay inside the subnet", 422)
        return f"{first} - {last}"
    try:
        pool_network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise AppError("INVALID_DHCP_POOL", "Pool must be an address range or CIDR", 422, str(exc)) from exc
    if pool_network.version != network.version or not pool_network.subnet_of(network):
        raise AppError("INVALID_DHCP_POOL", "Pool CIDR must stay inside the subnet", 422)
    return str(pool_network)


def _upsert_option(options: list[dict[str, Any]], name: str, data: str | None) -> None:
    options[:] = [item for item in options if item.get("name") != name]
    if data:
        options.append({"name": name, "data": data})


class DhcpService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()

    def _state_key(self, family: int) -> str:
        _family_root(family)
        return f"dhcp{family}_draft"

    def load_draft(self, family: int) -> dict[str, Any]:
        row = self.db.get(AppState, self._state_key(family))
        if row is None:
            return _default_config(family)
        try:
            value = json.loads(row.value)
        except json.JSONDecodeError as exc:
            raise AppError("DHCP_STATE_INVALID", "Stored DHCP draft is invalid JSON", 500, str(exc)) from exc
        if not isinstance(value, dict):
            raise AppError("DHCP_STATE_INVALID", "Stored DHCP draft must be a JSON object", 500)
        return _validate_document(family, value)

    def save_draft(self, family: int, document: dict[str, Any]) -> dict[str, Any]:
        value = _validate_document(family, deepcopy(document))
        key = self._state_key(family)
        row = self.db.get(AppState, key)
        encoded = json.dumps(value, sort_keys=True, indent=2)
        if row is None:
            self.db.add(AppState(key=key, value=encoded))
        else:
            row.value = encoded
        self.db.commit()
        return value

    def save_raw(self, family: int, raw: str) -> dict[str, Any]:
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AppError("INVALID_DHCP_JSON", "DHCP configuration is not valid JSON", 422, str(exc)) from exc
        if not isinstance(document, dict):
            raise AppError("INVALID_DHCP_JSON", "DHCP configuration must be a JSON object", 422)
        return self.save_draft(family, document)

    def set_global(self, family: int, payload: DhcpGlobalUpdate) -> dict[str, Any]:
        document = self.load_draft(family)
        body = document[_family_root(family)]
        body.setdefault("interfaces-config", {})["interfaces"] = payload.interfaces
        body["valid-lifetime"] = payload.valid_lifetime
        body["renew-timer"] = payload.renew_timer
        body["rebind-timer"] = payload.rebind_timer
        if family == 4:
            body["authoritative"] = payload.authoritative
        else:
            body["preferred-lifetime"] = payload.preferred_lifetime or min(payload.valid_lifetime, 1800)
        options = body.setdefault("option-data", [])
        if not isinstance(options, list):
            options = []
            body["option-data"] = options
        _upsert_option(options, "domain-name-servers" if family == 4 else "dns-servers", ", ".join(payload.dns_servers) or None)
        _upsert_option(options, "domain-name" if family == 4 else "domain-search", payload.domain_name)
        return self.save_draft(family, document)

    def _subnets(self, family: int, document: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        document = document or self.load_draft(family)
        result = document[_family_root(family)].setdefault(_subnet_key(family), [])
        if not isinstance(result, list):
            raise AppError("INVALID_DHCP_CONFIG", f"{_subnet_key(family)} must be a list", 422)
        return result

    def _find_subnet(self, family: int, subnet_id: int, document: dict[str, Any]) -> dict[str, Any]:
        for subnet in self._subnets(family, document):
            if int(subnet.get("id", -1)) == subnet_id:
                return subnet
        raise AppError("DHCP_SUBNET_NOT_FOUND", "DHCP subnet not found", 404)

    def add_subnet(self, family: int, payload: DhcpSubnetCreate) -> dict[str, Any]:
        try:
            network = ipaddress.ip_network(payload.subnet.strip(), strict=False)
        except ValueError as exc:
            raise AppError("INVALID_DHCP_SUBNET", "Invalid subnet CIDR", 422, str(exc)) from exc
        if network.version != family:
            raise AppError("INVALID_DHCP_SUBNET", f"Subnet must be IPv{family}", 422)
        document = self.load_draft(family)
        subnets = self._subnets(family, document)
        if any(str(item.get("subnet")) == str(network) for item in subnets):
            raise AppError("DHCP_SUBNET_EXISTS", "DHCP subnet already exists", 409)
        next_id = max([int(item.get("id", 0) or 0) for item in subnets] + [0]) + 1
        row: dict[str, Any] = {"id": next_id, "subnet": str(network), "pools": [], "reservations": [], "option-data": []}
        if payload.interface:
            row["interface"] = payload.interface.strip()
        if payload.pool:
            row["pools"].append({"pool": _normalize_pool(network, payload.pool)})
        if payload.valid_lifetime:
            row["valid-lifetime"] = payload.valid_lifetime
        if family == 4 and payload.routers:
            routers = [str(ipaddress.ip_address(item)) for item in payload.routers]
            if any(ipaddress.ip_address(item) not in network for item in routers):
                raise AppError("INVALID_DHCP_ROUTER", "Router address must belong to the subnet", 422)
            _upsert_option(row["option-data"], "routers", ", ".join(routers))
        dns_values = [str(ipaddress.ip_address(item)) for item in payload.dns_servers]
        if dns_values:
            _upsert_option(row["option-data"], "domain-name-servers" if family == 4 else "dns-servers", ", ".join(dns_values))
        if payload.domain_name:
            _upsert_option(row["option-data"], "domain-name" if family == 4 else "domain-search", payload.domain_name.strip().rstrip("."))
        subnets.append(row)
        return self.save_draft(family, document)

    def delete_subnet(self, family: int, subnet_id: int) -> dict[str, Any]:
        document = self.load_draft(family)
        subnets = self._subnets(family, document)
        old_size = len(subnets)
        subnets[:] = [item for item in subnets if int(item.get("id", -1)) != subnet_id]
        if len(subnets) == old_size:
            raise AppError("DHCP_SUBNET_NOT_FOUND", "DHCP subnet not found", 404)
        return self.save_draft(family, document)

    def add_pool(self, family: int, subnet_id: int, payload: DhcpPoolCreate) -> dict[str, Any]:
        document = self.load_draft(family)
        subnet = self._find_subnet(family, subnet_id, document)
        network = ipaddress.ip_network(str(subnet["subnet"]), strict=False)
        pool = _normalize_pool(network, payload.pool)
        pools = subnet.setdefault("pools", [])
        if any(item.get("pool") == pool for item in pools):
            raise AppError("DHCP_POOL_EXISTS", "DHCP pool already exists", 409)
        pools.append({"pool": pool})
        return self.save_draft(family, document)

    def delete_pool(self, family: int, subnet_id: int, pool_index: int) -> dict[str, Any]:
        document = self.load_draft(family)
        pools = self._find_subnet(family, subnet_id, document).setdefault("pools", [])
        if pool_index < 0 or pool_index >= len(pools):
            raise AppError("DHCP_POOL_NOT_FOUND", "DHCP pool not found", 404)
        pools.pop(pool_index)
        return self.save_draft(family, document)

    def add_reservation(self, family: int, subnet_id: int, payload: DhcpReservationCreate) -> dict[str, Any]:
        allowed = {4: {"hw-address", "client-id", "flex-id"}, 6: {"hw-address", "duid", "flex-id"}}
        if payload.identifier_type not in allowed[family]:
            raise AppError("INVALID_DHCP_IDENTIFIER", f"Identifier {payload.identifier_type} is not valid for DHCPv{family}", 422)
        document = self.load_draft(family)
        subnet = self._find_subnet(family, subnet_id, document)
        network = ipaddress.ip_network(str(subnet["subnet"]), strict=False)
        address = ipaddress.ip_address(payload.address)
        if address.version != family or address not in network:
            raise AppError("INVALID_DHCP_RESERVATION", "Reserved address must belong to the subnet", 422)
        reservation: dict[str, Any] = {payload.identifier_type: payload.identifier}
        reservation["ip-address" if family == 4 else "ip-addresses"] = str(address) if family == 4 else [str(address)]
        if payload.hostname:
            reservation["hostname"] = payload.hostname
        reservations = subnet.setdefault("reservations", [])
        if any(item.get(payload.identifier_type) == payload.identifier for item in reservations):
            raise AppError("DHCP_RESERVATION_EXISTS", "Reservation identifier already exists in this subnet", 409)
        reservations.append(reservation)
        return self.save_draft(family, document)

    def delete_reservation(self, family: int, subnet_id: int, reservation_index: int) -> dict[str, Any]:
        document = self.load_draft(family)
        reservations = self._find_subnet(family, subnet_id, document).setdefault("reservations", [])
        if reservation_index < 0 or reservation_index >= len(reservations):
            raise AppError("DHCP_RESERVATION_NOT_FOUND", "DHCP reservation not found", 404)
        reservations.pop(reservation_index)
        return self.save_draft(family, document)

    def add_option(self, family: int, payload: DhcpOptionCreate, subnet_id: int | None = None) -> dict[str, Any]:
        document = self.load_draft(family)
        target = document[_family_root(family)] if subnet_id is None else self._find_subnet(family, subnet_id, document)
        options = target.setdefault("option-data", [])
        option: dict[str, Any] = {"data": payload.data, "csv-format": payload.csv_format}
        if payload.name:
            option["name"] = payload.name
        if payload.code is not None:
            option["code"] = payload.code
        if payload.space:
            option["space"] = payload.space
        options.append(option)
        return self.save_draft(family, document)

    def delete_option(self, family: int, option_index: int, subnet_id: int | None = None) -> dict[str, Any]:
        document = self.load_draft(family)
        target = document[_family_root(family)] if subnet_id is None else self._find_subnet(family, subnet_id, document)
        options = target.setdefault("option-data", [])
        if option_index < 0 or option_index >= len(options):
            raise AppError("DHCP_OPTION_NOT_FOUND", "DHCP option not found", 404)
        options.pop(option_index)
        return self.save_draft(family, document)

    def interfaces(self) -> list[str]:
        return sorted({name for _, name in socket.if_nameindex() if name != "lo"})

    def _run_helper(self, *args: str, timeout: int = 60) -> str:
        command = [*self.settings.dhcp_helper, *args]
        if not command:
            raise AppError("DHCP_HELPER_NOT_CONFIGURED", "DHCP helper is not configured", 500)
        try:
            proc = subprocess.run(command, capture_output=True, text=True, shell=False, check=False, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AppError("DHCP_HELPER_FAILED", "Unable to execute DHCP helper", 500, str(exc)) from exc
        if proc.returncode != 0:
            raise AppError("DHCP_OPERATION_FAILED", "DHCP operation failed", 422, (proc.stderr or proc.stdout).strip())
        return proc.stdout

    def _staged_document(self, family: int, document: dict[str, Any]) -> Path:
        self.settings.staging_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f"dhcp{family}-", suffix=".json", dir=self.settings.staging_dir)
        path = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
        return path

    def validate_draft(self, family: int) -> str:
        path = self._staged_document(family, self.load_draft(family))
        try:
            return self._run_helper("validate", "--family", str(family), "--file", str(path), timeout=60).strip()
        finally:
            path.unlink(missing_ok=True)

    def apply_draft(self, family: int) -> str:
        path = self._staged_document(family, self.load_draft(family))
        try:
            return self._run_helper("apply", "--family", str(family), "--file", str(path), timeout=90).strip()
        finally:
            path.unlink(missing_ok=True)

    def import_active(self, family: int) -> dict[str, Any]:
        return self.save_raw(family, self._run_helper("read-config", "--family", str(family), timeout=30))

    def status(self, family: int) -> dict[str, Any]:
        raw = self._run_helper("status", "--family", str(family), timeout=30)
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AppError("DHCP_STATUS_INVALID", "DHCP helper returned invalid status", 500, str(exc)) from exc
        return result if isinstance(result, dict) else {"active": False, "error": "invalid status"}

    def service_action(self, family: int, action: str) -> str:
        _family_root(family)
        if action not in SERVICE_ACTIONS:
            raise AppError("INVALID_DHCP_ACTION", "Unsupported DHCP service action", 422)
        return self._run_helper("service", "--family", str(family), "--action", action, timeout=90).strip()

    def leases(self, family: int, limit: int = 250) -> list[dict[str, Any]]:
        raw = self._run_helper("leases", "--family", str(family), "--limit", str(max(1, min(limit, 2000))), timeout=30)
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AppError("DHCP_LEASES_INVALID", "DHCP helper returned invalid lease data", 500, str(exc)) from exc
        return result if isinstance(result, list) else []

    def logs(self, family: int, lines: int = 100) -> str:
        return self._run_helper("logs", "--family", str(family), "--lines", str(max(1, min(lines, 1000))), timeout=30)
