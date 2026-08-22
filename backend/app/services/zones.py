from __future__ import annotations

import difflib
import ipaddress
import os
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..errors import AppError
from ..models import Record, Zone, utcnow
from ..schemas import RecordCreate, RecordUpdate, ZoneCreate, ZoneUpdate
from .backup import BackupService
from .bind import BindService
from .serials import next_soa_serial
from .zonefile import parse_zone_text, render_zone, safe_zone_filename, sha256_file

_zone_locks: dict[str, threading.RLock] = {}
_zone_locks_guard = threading.Lock()


@contextmanager
def zone_lock(name: str):
    with _zone_locks_guard:
        lock = _zone_locks.setdefault(name, threading.RLock())
    with lock:
        yield


class ZoneService:
    def __init__(self, db: Session, bind: BindService | None = None, settings: Settings | None = None) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.bind = bind or BindService(self.settings)

    def get(self, name: str) -> Zone:
        zone = self.db.scalar(select(Zone).where(Zone.name == name.lower().rstrip(".")))
        if zone is None:
            raise AppError("ZONE_NOT_FOUND", "Zone not found", 404)
        return zone

    def _active_path(self, zone: Zone) -> Path:
        if zone.source_path and not zone.managed:
            return Path(zone.source_path)
        return self.settings.bind_zone_dir / zone.file_name

    def _check_external_change(self, zone: Zone) -> None:
        path = self._active_path(zone)
        if zone.file_hash and path.is_file():
            current = sha256_file(path)
            if current != zone.file_hash:
                raise AppError(
                    "ZONE_CHANGED_EXTERNALLY",
                    "Zone file changed outside ChrisLab-DNS",
                    409,
                    "Run Synchronize before editing so manual administrator changes are preserved.",
                )

    def _managed_config(self, exclude: str | None = None, override: Zone | None = None) -> str:
        zones = list(self.db.scalars(select(Zone).where(Zone.managed.is_(True)).order_by(Zone.name)))
        lines = ["// Managed by ChrisLab-DNS. Manual zones belong in named.conf.local outside this include."]
        seen_override = False
        for zone in zones:
            if exclude and zone.name == exclude:
                continue
            current = override if override and zone.name == override.name else zone
            if override and zone.name == override.name:
                seen_override = True
            if not current.enabled:
                continue
            path = self.settings.bind_zone_dir / current.file_name
            lines.extend([
                f'zone "{current.name}" {{',
                "    type master;",
                f'    file "{path}";',
                "    allow-update { none; };",
                "};",
                "",
            ])
        if override and not seen_override and override.enabled:
            path = self.settings.bind_zone_dir / override.file_name
            lines.extend([
                f'zone "{override.name}" {{',
                "    type master;",
                f'    file "{path}";',
                "    allow-update { none; };",
                "};",
                "",
            ])
        return "\n".join(lines).rstrip() + "\n"

    def _stage(self, zone_text: str, managed_text: str) -> tuple[Path, Path]:
        self.settings.staging_dir.mkdir(parents=True, exist_ok=True)
        zone_fd, zone_name = tempfile.mkstemp(prefix="zone-", suffix=".tmp", dir=self.settings.staging_dir)
        conf_fd, conf_name = tempfile.mkstemp(prefix="managed-", suffix=".conf", dir=self.settings.staging_dir)
        try:
            for fd, content in ((zone_fd, zone_text), (conf_fd, managed_text)):
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
        except Exception:
            Path(zone_name).unlink(missing_ok=True)
            Path(conf_name).unlink(missing_ok=True)
            raise
        return Path(zone_name), Path(conf_name)

    def _apply(self, zone: Zone, reason: str, username: str) -> str:
        zone_text = render_zone(zone)
        managed_text = self._managed_config(override=zone)
        staged_zone, staged_conf = self._stage(zone_text, managed_text)
        try:
            self.bind.validate_zone(zone.name, staged_zone)
            self.bind.validate_candidate(zone.name, staged_zone, zone.file_name, staged_conf)
            if self.settings.auto_backup:
                BackupService(self.db, self.bind, self.settings).create(reason, username)
            self.bind.apply_zone(zone.name, staged_zone, zone.file_name, staged_conf)
        finally:
            staged_zone.unlink(missing_ok=True)
            staged_conf.unlink(missing_ok=True)
        active = self.settings.bind_zone_dir / zone.file_name
        if active.is_file():
            zone.file_hash = sha256_file(active)
        zone.validation_status = "valid"
        zone.last_modified = utcnow()
        return zone_text

    def create(self, payload: ZoneCreate, username: str) -> Zone:
        name = payload.name
        with zone_lock(name):
            if self.db.scalar(select(Zone.id).where(Zone.name == name)) is not None:
                raise AppError("ZONE_EXISTS", "Zone already exists", 409)
            mname = (payload.soa_mname or f"ns1.{name}.").strip()
            rname = (payload.soa_rname or f"hostmaster.{name}.").strip()
            if not mname.endswith(".") or not rname.endswith("."):
                raise AppError("INVALID_SOA", "SOA MNAME and RNAME must end with a dot", 422)
            zone = Zone(
                name=name,
                zone_type=payload.zone_type,
                reverse=payload.reverse,
                enabled=payload.enabled,
                managed=True,
                file_name=safe_zone_filename(name),
                default_ttl=payload.default_ttl,
                soa_mname=mname,
                soa_rname=rname,
                serial=next_soa_serial(0),
                version=1,
            )
            zone.records.append(Record(name="@", type="NS", value=mname, ttl=payload.default_ttl))
            self.db.add(zone)
            self.db.flush()
            try:
                self._apply(zone, f"before CREATE_ZONE {name}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(zone)
            return zone


    def copy_zone(self, source: Zone, new_name: str, username: str) -> Zone:
        from ..schemas import normalize_zone_name
        name = normalize_zone_name(new_name)
        with zone_lock(name):
            if self.db.scalar(select(Zone.id).where(Zone.name == name)) is not None:
                raise AppError("ZONE_EXISTS", "Zone already exists", 409)
            zone = Zone(
                name=name, zone_type="primary", reverse=source.reverse, enabled=source.enabled, managed=True,
                file_name=safe_zone_filename(name), default_ttl=source.default_ttl,
                soa_mname=(source.soa_mname.replace(source.name + ".", name + ".") if source.soa_mname.endswith(source.name + ".") else source.soa_mname),
                soa_rname=(source.soa_rname.replace(source.name + ".", name + ".") if source.soa_rname.endswith(source.name + ".") else source.soa_rname),
                serial=next_soa_serial(0), refresh=source.refresh, retry=source.retry, expire=source.expire, minimum=source.minimum,
            )
            for item in source.records:
                value = item.value.replace(source.name + ".", name + ".") if item.value.endswith(source.name + ".") else item.value
                zone.records.append(Record(name=item.name, type=item.type, value=value, ttl=item.ttl, priority=item.priority, weight=item.weight, port=item.port))
            self.db.add(zone)
            self.db.flush()
            try:
                self._apply(zone, f"before COPY_ZONE {source.name} to {name}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(zone)
            return zone

    def create_reverse(self, network_text: str, username: str) -> Zone:
        network = ipaddress.ip_network(network_text, strict=False)
        octets = str(network.network_address).split(".")[: network.prefixlen // 8]
        name = ".".join(reversed(octets)) + ".in-addr.arpa"
        return self.create(ZoneCreate(name=name, reverse=True), username)

    def update(self, zone: Zone, payload: ZoneUpdate, username: str) -> Zone:
        with zone_lock(zone.name):
            self._check_external_change(zone)
            if zone.version != payload.version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            for field in ("enabled", "default_ttl", "soa_mname", "soa_rname"):
                value = getattr(payload, field)
                if value is not None:
                    setattr(zone, field, value)
            if not zone.soa_mname.endswith(".") or not zone.soa_rname.endswith("."):
                raise AppError("INVALID_SOA", "SOA MNAME and RNAME must end with a dot", 422)
            zone.serial = next_soa_serial(zone.serial)
            zone.version += 1
            self._apply(zone, f"before UPDATE_ZONE {zone.name}", username)
            self.db.commit()
            self.db.refresh(zone)
            return zone

    def preview_zone(self, zone: Zone, payload: ZoneUpdate) -> str:
        if zone.version != payload.version:
            raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
        old_text = render_zone(zone)
        fields = ("enabled", "default_ttl", "soa_mname", "soa_rname")
        old = {field: getattr(zone, field) for field in fields}
        old_serial = zone.serial
        try:
            for field in fields:
                value = getattr(payload, field)
                if value is not None:
                    setattr(zone, field, value)
            zone.serial = next_soa_serial(zone.serial)
            new_text = render_zone(zone)
        finally:
            for field, value in old.items():
                setattr(zone, field, value)
            zone.serial = old_serial
        return "".join(difflib.unified_diff(old_text.splitlines(True), new_text.splitlines(True), fromfile="current", tofile="proposed"))

    def delete(self, zone: Zone, username: str, version: int) -> None:
        with zone_lock(zone.name):
            self._check_external_change(zone)
            if zone.version != version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            managed_text = self._managed_config(exclude=zone.name)
            staged_zone, staged_conf = self._stage(render_zone(zone), managed_text)
            try:
                self.bind.validate_candidate(zone.name, None, zone.file_name, staged_conf, remove=True)
                if self.settings.auto_backup:
                    BackupService(self.db, self.bind, self.settings).create(f"before DELETE_ZONE {zone.name}", username)
                self.bind.remove_zone(zone.name, zone.file_name, staged_conf)
            finally:
                staged_zone.unlink(missing_ok=True)
                staged_conf.unlink(missing_ok=True)
            self.db.delete(zone)
            self.db.commit()

    def _ensure_record_unique(self, zone: Zone, payload: RecordCreate, exclude_id: int | None = None) -> None:
        stmt = select(Record.id).where(
            Record.zone_id == zone.id,
            Record.name == payload.name,
            Record.type == payload.type,
            Record.value == payload.value,
            Record.ttl == payload.ttl,
        )
        if payload.priority is None:
            stmt = stmt.where(Record.priority.is_(None))
        else:
            stmt = stmt.where(Record.priority == payload.priority)
        if payload.weight is None:
            stmt = stmt.where(Record.weight.is_(None))
        else:
            stmt = stmt.where(Record.weight == payload.weight)
        if payload.port is None:
            stmt = stmt.where(Record.port.is_(None))
        else:
            stmt = stmt.where(Record.port == payload.port)
        if exclude_id is not None:
            stmt = stmt.where(Record.id != exclude_id)
        if self.db.scalar(stmt) is not None:
            raise AppError("RECORD_EXISTS", "Identical record already exists", 409)

    def add_record(self, zone: Zone, payload: RecordCreate, username: str) -> Record:
        with zone_lock(zone.name):
            self._check_external_change(zone)
            if zone.version != payload.zone_version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            self._ensure_record_unique(zone, payload)
            record = Record(
                zone_id=zone.id, name=payload.name, type=payload.type, value=payload.value, ttl=payload.ttl,
                priority=payload.priority, weight=payload.weight, port=payload.port,
            )
            zone.records.append(record)
            zone.serial = next_soa_serial(zone.serial)
            zone.version += 1
            self.db.flush()
            try:
                self._apply(zone, f"before CREATE_RECORD {zone.name}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(record)
            return record

    def update_record(self, zone: Zone, record: Record, payload: RecordUpdate, username: str) -> Record:
        with zone_lock(zone.name):
            self._check_external_change(zone)
            if zone.version != payload.zone_version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            self._ensure_record_unique(zone, payload, record.id)
            for field in ("name", "type", "value", "ttl", "priority", "weight", "port"):
                setattr(record, field, getattr(payload, field))
            zone.serial = next_soa_serial(zone.serial)
            zone.version += 1
            self._apply(zone, f"before UPDATE_RECORD {zone.name}", username)
            self.db.commit()
            self.db.refresh(record)
            return record

    def delete_record(self, zone: Zone, record: Record, zone_version: int, username: str) -> None:
        with zone_lock(zone.name):
            self._check_external_change(zone)
            if zone.version != zone_version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            self.db.delete(record)
            zone.serial = next_soa_serial(zone.serial)
            zone.version += 1
            self.db.flush()
            try:
                self._apply(zone, f"before DELETE_RECORD {zone.name}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def preview_record(self, zone: Zone, payload: RecordCreate, record: Record | None = None) -> str:
        if zone.version != payload.zone_version:
            raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
        self._ensure_record_unique(zone, payload, record.id if record else None)
        old_text = render_zone(zone)
        old_serial = zone.serial
        zone.serial = next_soa_serial(zone.serial)
        try:
            if record is None:
                candidate = Record(
                    id=-1, zone_id=zone.id, name=payload.name, type=payload.type, value=payload.value, ttl=payload.ttl,
                    priority=payload.priority, weight=payload.weight, port=payload.port,
                )
                zone.records.append(candidate)
                try:
                    new_text = render_zone(zone)
                finally:
                    zone.records.remove(candidate)
            else:
                old = {field: getattr(record, field) for field in ("name", "type", "value", "ttl", "priority", "weight", "port")}
                try:
                    for field in old:
                        setattr(record, field, getattr(payload, field))
                    new_text = render_zone(zone)
                finally:
                    for field, value in old.items():
                        setattr(record, field, value)
        finally:
            zone.serial = old_serial
        return "".join(difflib.unified_diff(old_text.splitlines(True), new_text.splitlines(True), fromfile="current", tofile="proposed"))

    def import_zone(self, name: str, text: str, username: str, enabled: bool = True) -> Zone:
        parsed = parse_zone_text(name, text)
        with zone_lock(parsed.name):
            if self.db.scalar(select(Zone.id).where(Zone.name == parsed.name)) is not None:
                raise AppError("ZONE_EXISTS", "Zone already exists", 409)
            zone = Zone(
                name=parsed.name, zone_type="primary", reverse=parsed.name.endswith(".in-addr.arpa"), enabled=enabled,
                managed=True, file_name=safe_zone_filename(parsed.name), default_ttl=parsed.default_ttl,
                soa_mname=parsed.soa_mname, soa_rname=parsed.soa_rname, serial=parsed.serial,
                refresh=parsed.refresh, retry=parsed.retry, expire=parsed.expire, minimum=parsed.minimum,
            )
            for item in parsed.records:
                zone.records.append(Record(name=item.name, type=item.type, value=item.value, ttl=item.ttl, priority=item.priority, weight=item.weight, port=item.port))
            self.db.add(zone)
            self.db.flush()
            try:
                self._apply(zone, f"before IMPORT_ZONE {parsed.name}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(zone)
            return zone
