from __future__ import annotations

import base64
import secrets
import socket
import time
from datetime import datetime, timezone

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.tsigkeyring
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..errors import AppError
from ..models import DnsReplicationState, DnsServer, TsigKey, Zone
from ..schemas import DnsServerCreate, DnsServerUpdate, TsigKeyCreate
from ..security import decrypt_secret, encrypt_secret

SERIAL_MODULUS = 1 << 32
SERIAL_HALF = 1 << 31
TRANSFER_TYPES = {"AXFR", "IXFR"}


def generate_tsig_secret() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def validate_tsig_secret(value: str) -> str:
    secret = value.strip()
    try:
        decoded = base64.b64decode(secret, validate=True)
    except Exception as exc:
        raise AppError("INVALID_TSIG_SECRET", "TSIG secret must be valid base64", 422) from exc
    if len(decoded) < 16:
        raise AppError("INVALID_TSIG_SECRET", "TSIG secret must contain at least 128 bits", 422)
    return secret


def compare_dns_serial(remote: int, expected: int) -> tuple[str, int]:
    """Compare RFC 1982-style 32-bit serials.

    Returns (status, lag). ``lag`` is the modular distance from a lagging remote
    server to the expected serial and is zero for equal/ahead states.
    """

    remote &= 0xFFFFFFFF
    expected &= 0xFFFFFFFF
    if remote == expected:
        return "in_sync", 0
    forward = (remote - expected) % SERIAL_MODULUS
    if 0 < forward < SERIAL_HALF:
        return "ahead", 0
    return "lagging", (expected - remote) % SERIAL_MODULUS


class DnsPlatformService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_servers(self) -> list[DnsServer]:
        return list(self.db.scalars(select(DnsServer).order_by(DnsServer.name)))

    def create_server(self, payload: DnsServerCreate) -> DnsServer:
        if payload.tsig_key_name and self.db.scalar(select(TsigKey.id).where(TsigKey.name == payload.tsig_key_name)) is None:
            raise AppError("TSIG_KEY_NOT_FOUND", "TSIG key not found", 422)
        row = DnsServer(**payload.model_dump())
        self.db.add(row)
        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            raise AppError("DNS_SERVER_EXISTS", "DNS server name already exists", 409) from exc
        self.db.refresh(row)
        return row

    def update_server(self, row: DnsServer, payload: DnsServerUpdate) -> DnsServer:
        values = payload.model_dump(exclude_unset=True)
        if values.get("tsig_key_name") and self.db.scalar(select(TsigKey.id).where(TsigKey.name == values["tsig_key_name"])) is None:
            raise AppError("TSIG_KEY_NOT_FOUND", "TSIG key not found", 422)
        for key, value in values.items():
            setattr(row, key, value)
        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            raise AppError("DNS_SERVER_EXISTS", "DNS server name already exists", 409) from exc
        self.db.refresh(row)
        return row

    def delete_server(self, row: DnsServer) -> None:
        self.db.delete(row)
        self.db.commit()

    def check_server(self, row: DnsServer, timeout: float = 2.0) -> dict[str, object]:
        started = datetime.now(timezone.utc)
        status = "unreachable"
        latency_ms: int | None = None
        try:
            before = time.monotonic()
            with socket.create_connection((row.address, 53), timeout=timeout):
                pass
            latency_ms = max(0, int((time.monotonic() - before) * 1000))
            status = "reachable"
        except OSError:
            status = "unreachable"
        row.last_check_at = started
        row.last_check_status = status
        self.db.commit()
        return {"status": status, "latency_ms": latency_ms, "checked_at": started}

    def list_tsig_keys(self) -> list[TsigKey]:
        return list(self.db.scalars(select(TsigKey).order_by(TsigKey.name)))

    def create_tsig_key(self, payload: TsigKeyCreate) -> tuple[TsigKey, str]:
        raw_secret = validate_tsig_secret(payload.secret) if payload.secret else generate_tsig_secret()
        row = TsigKey(name=payload.name, algorithm=payload.algorithm, secret_encrypted=encrypt_secret(raw_secret))
        self.db.add(row)
        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            raise AppError("TSIG_KEY_EXISTS", "TSIG key name already exists", 409) from exc
        self.db.refresh(row)
        return row, raw_secret

    def rotate_tsig_key(self, row: TsigKey, *, commit: bool = True) -> str:
        raw_secret = generate_tsig_secret()
        row.secret_encrypted = encrypt_secret(raw_secret)
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        return raw_secret

    def delete_tsig_key(self, row: TsigKey, *, commit: bool = True) -> None:
        zone = self.db.scalar(select(Zone.name).where(Zone.tsig_key_name == row.name).limit(1))
        server = self.db.scalar(select(DnsServer.name).where(DnsServer.tsig_key_name == row.name).limit(1))
        if zone or server:
            details = f"used by zone {zone}" if zone else f"used by DNS server {server}"
            raise AppError("TSIG_KEY_IN_USE", "TSIG key is still in use", 409, details)
        self.db.delete(row)
        if commit:
            self.db.commit()
        else:
            self.db.flush()

    @staticmethod
    def plaintext_tsig_secret(row: TsigKey) -> str:
        secret = decrypt_secret(row.secret_encrypted)
        if not secret:
            raise AppError("TSIG_SECRET_UNAVAILABLE", "TSIG secret cannot be decrypted", 500)
        return secret

    def _tsig(self, key_name: str | None) -> tuple[object | None, str | None, str | None]:
        if not key_name:
            return None, None, None
        row = self.db.scalar(select(TsigKey).where(TsigKey.name == key_name))
        if row is None:
            raise AppError("TSIG_KEY_NOT_FOUND", "TSIG key not found", 422, key_name)
        secret = self.plaintext_tsig_secret(row)
        fqdn_name = row.name if row.name.endswith(".") else row.name + "."
        algorithm = row.algorithm if row.algorithm.endswith(".") else row.algorithm + "."
        return dns.tsigkeyring.from_text({fqdn_name: secret}), fqdn_name, algorithm

    def _sign_query(self, query: dns.message.Message, key_name: str | None) -> None:
        keyring, fqdn_name, algorithm = self._tsig(key_name)
        if keyring is not None and fqdn_name is not None and algorithm is not None:
            query.use_tsig(keyring, keyname=fqdn_name, algorithm=algorithm)

    def _query_soa(self, address: str, zone: Zone, key_name: str | None = None, timeout: float = 3.0) -> dict[str, object]:
        query = dns.message.make_query(zone.name + ".", dns.rdatatype.SOA)
        self._sign_query(query, key_name)
        started = time.monotonic()
        response = dns.query.udp(query, address, timeout=timeout)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, address, timeout=timeout)
        latency_ms = max(0, int((time.monotonic() - started) * 1000))
        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            return {
                "status": "query_error",
                "serial": None,
                "authoritative": bool(response.flags & dns.flags.AA),
                "latency_ms": latency_ms,
                "details": dns.rcode.to_text(rcode),
            }
        serial: int | None = None
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.SOA and len(rrset):
                serial = int(rrset[0].serial)
                break
        if serial is None:
            return {
                "status": "not_authoritative" if not (response.flags & dns.flags.AA) else "soa_missing",
                "serial": None,
                "authoritative": bool(response.flags & dns.flags.AA),
                "latency_ms": latency_ms,
                "details": "SOA answer missing",
            }
        return {
            "status": "ok",
            "serial": serial,
            "authoritative": bool(response.flags & dns.flags.AA),
            "latency_ms": latency_ms,
            "details": None,
        }

    def _query_soa_safe(self, address: str, zone: Zone, key_name: str | None = None, timeout: float = 3.0) -> dict[str, object]:
        try:
            return self._query_soa(address, zone, key_name, timeout)
        except Exception as exc:
            return {
                "status": "unreachable",
                "serial": None,
                "authoritative": False,
                "latency_ms": None,
                "details": str(exc),
            }

    @staticmethod
    def _newest_serial(serials: list[int]) -> int | None:
        if not serials:
            return None
        newest = serials[0] & 0xFFFFFFFF
        for candidate in serials[1:]:
            status, _ = compare_dns_serial(candidate, newest)
            if status == "ahead":
                newest = candidate & 0xFFFFFFFF
        return newest

    def _expected_serial(self, zone: Zone) -> tuple[int | None, list[dict[str, object]]]:
        if zone.zone_type != "secondary":
            return int(zone.serial), []
        sources: list[dict[str, object]] = []
        serials: list[int] = []
        for address in zone.primary_servers or []:
            probe = self._query_soa_safe(address, zone, zone.tsig_key_name)
            item = {"address": address, **probe}
            sources.append(item)
            if isinstance(probe.get("serial"), int):
                serials.append(int(probe["serial"]))
        return self._newest_serial(serials), sources

    def _replication_state(self, server: DnsServer, zone: Zone) -> DnsReplicationState:
        row = self.db.scalar(
            select(DnsReplicationState).where(
                DnsReplicationState.server_id == server.id,
                DnsReplicationState.zone_id == zone.id,
            )
        )
        if row is None:
            row = DnsReplicationState(server_id=server.id, zone_id=zone.id)
            self.db.add(row)
            self.db.flush()
        return row

    def probe_replication(self, server: DnsServer, zone: Zone, expected_serial: int | None = None, *, commit: bool = True) -> dict[str, object]:
        checked_at = datetime.now(timezone.utc)
        probe = self._query_soa_safe(server.address, zone, server.tsig_key_name or zone.tsig_key_name)
        serial = probe.get("serial") if isinstance(probe.get("serial"), int) else None
        status = str(probe["status"])
        lag: int | None = None
        if serial is not None and expected_serial is not None:
            status, lag = compare_dns_serial(serial, expected_serial)
        elif serial is not None:
            status = "serial_unknown"

        state = self._replication_state(server, zone)
        state.last_probe_at = checked_at
        state.last_status = status
        state.last_serial = serial
        state.serial_lag = lag
        state.authoritative = bool(probe.get("authoritative"))
        state.latency_ms = probe.get("latency_ms") if isinstance(probe.get("latency_ms"), int) else None
        if status == "in_sync":
            state.last_in_sync_at = checked_at
        server.last_check_at = checked_at
        server.last_check_status = "reachable" if serial is not None else "unreachable"
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        return {
            "server_id": server.id,
            "server": server.name,
            "address": server.address,
            "role": server.role,
            "status": status,
            "serial": serial,
            "expected_serial": expected_serial,
            "serial_lag": lag,
            "authoritative": bool(probe.get("authoritative")),
            "latency_ms": probe.get("latency_ms"),
            "checked_at": checked_at,
            "last_in_sync_at": state.last_in_sync_at,
            "details": probe.get("details"),
        }

    def replication_report(self, zone: Zone) -> dict[str, object]:
        expected_serial, primary_sources = self._expected_serial(zone)
        local = self._query_soa_safe("127.0.0.1", zone, None)
        local_serial = local.get("serial") if isinstance(local.get("serial"), int) else None
        local_status = str(local["status"])
        local_lag: int | None = None
        if local_serial is not None and expected_serial is not None:
            local_status, local_lag = compare_dns_serial(local_serial, expected_serial)

        servers = list(self.db.scalars(select(DnsServer).where(DnsServer.enabled.is_(True)).order_by(DnsServer.name)))
        remote = [self.probe_replication(server, zone, expected_serial, commit=False) for server in servers]
        self.db.commit()
        return {
            "zone": zone.name,
            "zone_type": zone.zone_type,
            "expected_serial": expected_serial,
            "configured_primary_sources": primary_sources,
            "local": {
                "address": "127.0.0.1",
                "status": local_status,
                "serial": local_serial,
                "expected_serial": expected_serial,
                "serial_lag": local_lag,
                "authoritative": bool(local.get("authoritative")),
                "latency_ms": local.get("latency_ms"),
                "details": local.get("details"),
            },
            "servers": remote,
        }

    def replication_overview(self) -> list[dict[str, object]]:
        zones = list(self.db.scalars(select(Zone).where(Zone.enabled.is_(True)).order_by(Zone.name)))
        return [self.replication_report(zone) for zone in zones]

    def _transfer_probe(self, server: DnsServer, zone: Zone, transfer_type: str, timeout: float = 5.0) -> dict[str, object]:
        normalized = transfer_type.upper()
        if normalized not in TRANSFER_TYPES:
            raise AppError("INVALID_TRANSFER_TYPE", "Transfer type must be AXFR or IXFR", 422)
        query = dns.message.make_query(zone.name + ".", dns.rdatatype.from_text(normalized))
        if normalized == "IXFR":
            mname = zone.soa_mname if zone.soa_mname.endswith(".") else zone.soa_mname + "."
            rname = zone.soa_rname if zone.soa_rname.endswith(".") else zone.soa_rname + "."
            query.authority.append(
                dns.rrset.from_text(
                    zone.name + ".",
                    zone.default_ttl,
                    "IN",
                    "SOA",
                    f"{mname} {rname} {zone.serial} {zone.refresh} {zone.retry} {zone.expire} {zone.minimum}",
                )
            )
        self._sign_query(query, server.tsig_key_name or zone.tsig_key_name)
        started = time.monotonic()
        response = dns.query.tcp(query, server.address, timeout=timeout)
        latency_ms = max(0, int((time.monotonic() - started) * 1000))
        rcode = response.rcode()
        return {
            "allowed": rcode == dns.rcode.NOERROR and bool(response.answer),
            "rcode": dns.rcode.to_text(rcode),
            "answer_rrsets": len(response.answer),
            "latency_ms": latency_ms,
        }

    def test_transfer(self, server: DnsServer, zone: Zone, transfer_type: str) -> dict[str, object]:
        checked_at = datetime.now(timezone.utc)
        normalized = transfer_type.upper()
        state = self._replication_state(server, zone)
        try:
            probe = self._transfer_probe(server, zone, normalized)
            status = "success" if probe["allowed"] else "refused"
            details = f"rcode={probe['rcode']} answer_rrsets={probe['answer_rrsets']}"
        except AppError:
            raise
        except Exception as exc:
            probe = {"allowed": False, "rcode": None, "answer_rrsets": 0, "latency_ms": None}
            status = "failed"
            details = str(exc)
        state.last_transfer_test_at = checked_at
        state.last_transfer_test_type = normalized
        state.last_transfer_test_status = status
        state.last_transfer_test_details = details
        if status == "success":
            state.last_transfer_ok_at = checked_at
        self.db.commit()
        return {
            "zone": zone.name,
            "server_id": server.id,
            "server": server.name,
            "address": server.address,
            "type": normalized,
            "status": status,
            "checked_at": checked_at,
            "last_transfer_ok_at": state.last_transfer_ok_at,
            "details": details,
            **probe,
        }


# ZoneService already owns the transactional zone/BIND apply path. Expose a
# config refresh method there without duplicating privileged-helper logic. This
# is used after TSIG rotation/deletion so database and active BIND state change
# within the same request transaction.
def _install_zone_config_refresh() -> None:
    from .zones import ZoneService

    def apply_managed_config_only(self: ZoneService, reason: str, username: str) -> None:
        carrier = self.db.scalar(select(Zone).where(Zone.managed.is_(True)).order_by(Zone.id).limit(1))
        if carrier is None:
            return
        self._apply(carrier, reason, username)

    if not hasattr(ZoneService, "apply_managed_config_only"):
        setattr(ZoneService, "apply_managed_config_only", apply_managed_config_only)


_install_zone_config_refresh()
