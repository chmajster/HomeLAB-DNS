from __future__ import annotations

import hashlib
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..errors import AppError
from ..models import Record, Zone
from .bind import BindService
from .zonefile import parse_zone_text


class SyncService:
    def __init__(self, db: Session, bind: BindService | None = None) -> None:
        self.db = db
        self.bind = bind or BindService()

    def compare(self) -> dict[str, list[dict[str, object]]]:
        discovered = self.bind.discover_zones()
        db_zones = {zone.name: zone for zone in self.db.scalars(select(Zone))}
        bind_zones = {str(item.get("name", "")).rstrip(".").lower(): item for item in discovered if item.get("name")}
        missing = [item for name, item in bind_zones.items() if name not in db_zones]
        absent = [{"name": zone.name, "file": zone.source_path or zone.file_name} for name, zone in db_zones.items() if name not in bind_zones and zone.enabled]
        changed: list[dict[str, object]] = []
        for name, item in bind_zones.items():
            zone = db_zones.get(name)
            if zone is None or not zone.file_hash:
                continue
            try:
                text = self.bind.read_zone(str(item.get("file", "")))
            except AppError:
                continue
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if digest != zone.file_hash:
                changed.append({"name": name, "file": item.get("file"), "database_hash": zone.file_hash, "bind_hash": digest})
        return {"missing_in_database": missing, "missing_in_bind": absent, "changed": changed}

    def import_missing(self, names: list[str] | None = None) -> list[str]:
        discovered = self.bind.discover_zones()
        existing = set(self.db.scalars(select(Zone.name)))
        requested = {name.rstrip(".").lower() for name in names} if names else None
        imported: list[str] = []
        for item in discovered:
            name = str(item.get("name", "")).rstrip(".").lower()
            if not name or name in existing or (requested is not None and name not in requested):
                continue
            zone_type = str(item.get("type", "master"))
            if zone_type not in {"master", "primary"}:
                continue
            path = str(item.get("file", ""))
            if not path:
                continue
            text = self.bind.read_zone(path)
            parsed = parse_zone_text(name, text)
            zone = Zone(
                name=name,
                zone_type="primary",
                reverse=name.endswith(".in-addr.arpa"),
                enabled=True,
                managed=False,
                file_name=Path(path).name,
                source_path=path,
                file_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                default_ttl=parsed.default_ttl,
                soa_mname=parsed.soa_mname,
                soa_rname=parsed.soa_rname,
                serial=parsed.serial,
                refresh=parsed.refresh,
                retry=parsed.retry,
                expire=parsed.expire,
                minimum=parsed.minimum,
            )
            for record in parsed.records:
                zone.records.append(Record(
                    name=record.name, type=record.type, value=record.value, ttl=record.ttl,
                    priority=record.priority, weight=record.weight, port=record.port,
                ))
            self.db.add(zone)
            imported.append(name)
        self.db.commit()
        return imported
