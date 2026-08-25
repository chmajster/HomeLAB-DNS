from __future__ import annotations

import base64
import secrets
import socket
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..errors import AppError
from ..models import DnsServer, TsigKey, Zone
from ..schemas import DnsServerCreate, DnsServerUpdate, TsigKeyCreate
from ..security import decrypt_secret, encrypt_secret


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
            before = datetime.now(timezone.utc)
            with socket.create_connection((row.address, 53), timeout=timeout):
                pass
            after = datetime.now(timezone.utc)
            latency_ms = max(0, int((after - before).total_seconds() * 1000))
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
