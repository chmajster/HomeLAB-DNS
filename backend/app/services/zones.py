from __future__ import annotations

import difflib
import ipaddress
import json
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..errors import AppError
from ..models import Record, TsigKey, Zone, ZoneRevision, utcnow
from ..schemas import RecordCreate, RecordUpdate, ZoneCreate, ZoneUpdate
from ..security import decrypt_secret
from .backup import BackupService
from .bind import BindService
from .serials import next_soa_serial
from .zonefile import parse_zone_text, render_zone, safe_zone_filename, sha256_file

_zone_locks: dict[str, threading.RLock] = {}
_zone_locks_guard = threading.Lock()
_TSIG_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")


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
        if zone.zone_type == "secondary":
            return
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

    def _get_tsig(self, name: str | None) -> TsigKey | None:
        if not name:
            return None
        if not _TSIG_NAME_RE.fullmatch(name):
            raise AppError("INVALID_TSIG_KEY", "Invalid TSIG key name", 422)
        row = self.db.scalar(select(TsigKey).where(TsigKey.name == name))
        if row is None:
            raise AppError("TSIG_KEY_NOT_FOUND", f"TSIG key not found: {name}", 422)
        return row

    def _zone_stanza(self, zone: Zone) -> list[str]:
        lines = [f'zone "{zone.name}" {{']
        if zone.zone_type == "secondary":
            if not zone.primary_servers:
                raise AppError("SECONDARY_PRIMARY_REQUIRED", "Secondary zone requires at least one primary server", 422)
            self._get_tsig(zone.tsig_key_name)
            lines.append("    type secondary;")
            lines.append("    primaries {")
            for address in zone.primary_servers:
                suffix = f' key "{zone.tsig_key_name}"' if zone.tsig_key_name else ""
                lines.append(f"        {address}{suffix};")
            lines.append("    };")
        else:
            path = self.settings.bind_zone_dir / zone.file_name
            self._get_tsig(zone.tsig_key_name)
            lines.extend([
                "    type master;",
                f'    file "{path}";',
                "    allow-update { none; };",
            ])
            transfer_acl: list[str] = []
            if zone.tsig_key_name:
                transfer_acl.append(f'key "{zone.tsig_key_name}";')
            transfer_acl.extend(f"{address};" for address in (zone.allow_transfer or []))
            if transfer_acl:
                lines.append("    allow-transfer {")
                lines.extend(f"        {entry}" for entry in transfer_acl)
                lines.append("    };")
            else:
                lines.append("    allow-transfer { none; };")
            if zone.also_notify:
                lines.append("    also-notify {")
                for address in zone.also_notify:
                    suffix = f' key "{zone.tsig_key_name}"' if zone.tsig_key_name else ""
                    lines.append(f"        {address}{suffix};")
                lines.append("    };")
                lines.append("    notify yes;")
        lines.extend(["};", ""])
        return lines

    def _managed_config(self, exclude: str | None = None, override: Zone | None = None) -> str:
        zones = list(self.db.scalars(select(Zone).where(Zone.managed.is_(True)).order_by(Zone.name)))
        keys = list(self.db.scalars(select(TsigKey).order_by(TsigKey.name)))
        lines = ["// Managed by ChrisLab-DNS. Manual zones belong in named.conf.local outside this include."]
        for key in keys:
            if not _TSIG_NAME_RE.fullmatch(key.name):
                raise AppError("INVALID_TSIG_KEY", "Stored TSIG key name is invalid", 500)
            secret = decrypt_secret(key.secret_encrypted)
            if not secret:
                raise AppError("TSIG_SECRET_UNAVAILABLE", f"Cannot decrypt TSIG key: {key.name}", 500)
            lines.extend([
                f'key "{key.name}" {{',
                f"    algorithm {key.algorithm};",
                f'    secret "{secret}";',
                "};",
                "",
            ])
        seen_override = False
        for zone in zones:
            if exclude and zone.name == exclude:
                continue
            current = override if override and zone.name == override.name else zone
            if override and zone.name == override.name:
                seen_override = True
            if not current.enabled:
                continue
            lines.extend(self._zone_stanza(current))
        if override and not seen_override and override.enabled:
            lines.extend(self._zone_stanza(override))
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
        # Secondary zones use a syntactically valid local placeholder file only
        # for the existing transactional helper. BIND ignores that file because
        # the generated stanza is type secondary and transfers authoritative data
        # from the configured primary servers.
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
        zone.validation_status = "secondary-configured" if zone.zone_type == "secondary" else "valid"
        zone.last_modified = utcnow()
        return zone_text

    def _snapshot(self, zone: Zone) -> dict[str, object]:
        return {
            "name": zone.name,
            "zone_type": zone.zone_type,
            "reverse": zone.reverse,
            "enabled": zone.enabled,
            "default_ttl": zone.default_ttl,
            "soa_mname": zone.soa_mname,
            "soa_rname": zone.soa_rname,
            "serial": zone.serial,
            "refresh": zone.refresh,
            "retry": zone.retry,
            "expire": zone.expire,
            "minimum": zone.minimum,
            "primary_servers": list(zone.primary_servers or []),
            "allow_transfer": list(zone.allow_transfer or []),
            "also_notify": list(zone.also_notify or []),
            "tsig_key_name": zone.tsig_key_name,
            "records": [
                {
                    "name": item.name,
                    "type": item.type,
                    "value": item.value,
                    "ttl": item.ttl,
                    "priority": item.priority,
                    "weight": item.weight,
                    "port": item.port,
                }
                for item in zone.records
            ],
        }

    def _record_revision(self, zone: Zone, reason: str, username: str) -> ZoneRevision:
        revision = ZoneRevision(
            zone_name=zone.name,
            version=zone.version,
            serial=zone.serial,
            snapshot_json=json.dumps(self._snapshot(zone), sort_keys=True),
            reason=reason[:255],
            created_by=username[:120],
        )
        self.db.add(revision)
        self.db.flush()
        return revision

    def list_revisions(self, zone_name: str, limit: int = 100) -> list[ZoneRevision]:
        return list(
            self.db.scalars(
                select(ZoneRevision)
                .where(ZoneRevision.zone_name == zone_name)
                .order_by(ZoneRevision.created_at.desc(), ZoneRevision.id.desc())
                .limit(max(1, min(limit, 500)))
            )
        )

    def restore_revision(self, zone: Zone, revision: ZoneRevision, version: int, username: str) -> Zone:
        with zone_lock(zone.name):
            self._check_external_change(zone)
            if revision.zone_name != zone.name:
                raise AppError("REVISION_NOT_FOUND", "Revision does not belong to this zone", 404)
            if zone.version != version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            try:
                snapshot = json.loads(revision.snapshot_json)
            except json.JSONDecodeError as exc:
                raise AppError("REVISION_INVALID", "Stored zone revision is invalid", 500) from exc
            self._record_revision(zone, f"before RESTORE_REVISION {revision.id}", username)
            current_serial = zone.serial
            current_version = zone.version
            for field in (
                "zone_type", "reverse", "enabled", "default_ttl", "soa_mname", "soa_rname",
                "refresh", "retry", "expire", "minimum", "primary_servers", "allow_transfer",
                "also_notify", "tsig_key_name",
            ):
                if field in snapshot:
                    setattr(zone, field, snapshot[field])
            zone.records.clear()
            for item in snapshot.get("records", []):
                zone.records.append(Record(**item))
            zone.serial = next_soa_serial(max(current_serial, int(snapshot.get("serial", 0))))
            zone.version = current_version + 1
            self.db.flush()
            try:
                self._apply(zone, f"before RESTORE_REVISION {revision.id}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(zone)
            return zone

    def create(self, payload: ZoneCreate, username: str) -> Zone:
        name = payload.name
        with zone_lock(name):
            if self.db.scalar(select(Zone.id).where(Zone.name == name)) is not None:
                raise AppError("ZONE_EXISTS", "Zone already exists", 409)
            mname = (payload.soa_mname or f"ns1.{name}.").strip()
            rname = (payload.soa_rname or f"hostmaster.{name}.").strip()
            if not mname.endswith(".") or not rname.endswith("."):
                raise AppError("INVALID_SOA", "SOA MNAME and RNAME must end with a dot", 422)
            if payload.tsig_key_name:
                self._get_tsig(payload.tsig_key_name)
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
                primary_servers=list(payload.primary_servers),
                allow_transfer=list(payload.allow_transfer),
                also_notify=list(payload.also_notify),
                tsig_key_name=payload.tsig_key_name,
            )
            # The placeholder NS keeps the staged file valid for both primary and
            # secondary zones. Secondary BIND stanzas do not reference this file.
            zone.records.append(Record(name="@", type="NS", value=mname, ttl=payload.default_ttl))
            self.db.add(zone)
            self.db.flush()
            try:
                self._apply(zone, f"before CREATE_ZONE {name}", username)
                self._record_revision(zone, "CREATE_ZONE", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(zone)
            return zone

    def copy_zone(self, source: Zone, new_name: str, username: str) -> Zone:
        from ..schemas import normalize_zone_name

        if source.zone_type != "primary":
            raise AppError("ZONE_COPY_UNSUPPORTED", "Only primary zones can be copied", 422)
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
                allow_transfer=list(source.allow_transfer or []), also_notify=list(source.also_notify or []), tsig_key_name=source.tsig_key_name,
            )
            for item in source.records:
                value = item.value.replace(source.name + ".", name + ".") if item.value.endswith(source.name + ".") else item.value
                zone.records.append(Record(name=item.name, type=item.type, value=value, ttl=item.ttl, priority=item.priority, weight=item.weight, port=item.port))
            self.db.add(zone)
            self.db.flush()
            try:
                self._apply(zone, f"before COPY_ZONE {source.name} to {name}", username)
                self._record_revision(zone, f"COPY_ZONE from {source.name}", username)
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
            self._record_revision(zone, "before UPDATE_ZONE", username)
            fields = (
                "enabled", "default_ttl", "soa_mname", "soa_rname", "primary_servers",
                "allow_transfer", "also_notify", "tsig_key_name",
            )
            for field in fields:
                value = getattr(payload, field)
                if value is not None:
                    setattr(zone, field, value)
            if zone.tsig_key_name:
                self._get_tsig(zone.tsig_key_name)
            if zone.zone_type == "secondary":
                if not zone.primary_servers:
                    raise AppError("SECONDARY_PRIMARY_REQUIRED", "Secondary zone requires at least one primary server", 422)
                if zone.allow_transfer or zone.also_notify:
                    raise AppError("INVALID_SECONDARY_POLICY", "Secondary zones cannot define allow_transfer or also_notify", 422)
            elif zone.primary_servers:
                raise AppError("INVALID_PRIMARY_POLICY", "Primary zones cannot define primary_servers", 422)
            if not zone.soa_mname.endswith(".") or not zone.soa_rname.endswith("."):
                raise AppError("INVALID_SOA", "SOA MNAME and RNAME must end with a dot", 422)
            zone.serial = next_soa_serial(zone.serial)
            zone.version += 1
            try:
                self._apply(zone, f"before UPDATE_ZONE {zone.name}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(zone)
            return zone

    def preview_zone(self, zone: Zone, payload: ZoneUpdate) -> str:
        if zone.version != payload.version:
            raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
        fields = (
            "enabled", "default_ttl", "soa_mname", "soa_rname", "primary_servers",
            "allow_transfer", "also_notify", "tsig_key_name",
        )
        old = {field: getattr(zone, field) for field in fields}
        old_serial = zone.serial
        old_text = render_zone(zone) + "\n" + "\n".join(self._zone_stanza(zone))
        try:
            for field in fields:
                value = getattr(payload, field)
                if value is not None:
                    setattr(zone, field, value)
            zone.serial = next_soa_serial(zone.serial)
            new_text = render_zone(zone) + "\n" + "\n".join(self._zone_stanza(zone))
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
            self._record_revision(zone, "before DELETE_ZONE", username)
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

    def _require_primary(self, zone: Zone) -> None:
        if zone.zone_type != "primary":
            raise AppError("SECONDARY_ZONE_READ_ONLY", "Records in secondary zones are transferred from the primary server", 409)

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
            self._require_primary(zone)
            self._check_external_change(zone)
            if zone.version != payload.zone_version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            self._ensure_record_unique(zone, payload)
            self._record_revision(zone, "before CREATE_RECORD", username)
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
            self._require_primary(zone)
            self._check_external_change(zone)
            if zone.version != payload.zone_version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            self._ensure_record_unique(zone, payload, record.id)
            self._record_revision(zone, "before UPDATE_RECORD", username)
            for field in ("name", "type", "value", "ttl", "priority", "weight", "port"):
                setattr(record, field, getattr(payload, field))
            zone.serial = next_soa_serial(zone.serial)
            zone.version += 1
            try:
                self._apply(zone, f"before UPDATE_RECORD {zone.name}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(record)
            return record

    def delete_record(self, zone: Zone, record: Record, zone_version: int, username: str) -> None:
        with zone_lock(zone.name):
            self._require_primary(zone)
            self._check_external_change(zone)
            if zone.version != zone_version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            self._record_revision(zone, "before DELETE_RECORD", username)
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
        self._require_primary(zone)
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
                self._record_revision(zone, "IMPORT_ZONE", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self.db.refresh(zone)
            return zone
