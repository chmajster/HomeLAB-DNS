from __future__ import annotations

import io
import tarfile

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from fastapi.responses import PlainTextResponse, Response, StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import enforce_api_csrf, require_permission
from ..errors import AppError
from ..models import Record, Zone, ZoneRevision
from ..schemas import (
    BulkRecordRequest,
    RecordCreate,
    RecordOut,
    RecordUpdate,
    ReverseZoneRequest,
    ZoneCreate,
    ZoneOut,
    ZoneRestoreRequest,
    ZoneRevisionOut,
    ZoneUpdate,
)
from ..security import Principal, get_client_ip
from ..services.audit import write_audit
from ..services.zones import ZoneService
from ..services.zonefile import render_zone

router = APIRouter(prefix="/zones", tags=["Zones"])


def _zone_out(zone: Zone) -> ZoneOut:
    return ZoneOut.model_validate(zone).model_copy(update={"record_count": len(zone.records)})


@router.get("", response_model=dict, summary="List DNS zones", description="Requires zones.read.")
def list_zones(
    q: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    page: int | None = Query(None, ge=1),
    page_size: int | None = Query(None, ge=1, le=200),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.read")),
):
    if page is not None or page_size is not None:
        effective_size = page_size or limit
        effective_page = page or 1
        limit, offset = effective_size, (effective_page - 1) * effective_size
    stmt = select(Zone).order_by(Zone.name)
    count_stmt = select(func.count(Zone.id))
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(Zone.name.ilike(pattern))
        count_stmt = count_stmt.where(Zone.name.ilike(pattern))
    total = db.scalar(count_stmt) or 0
    items = list(db.scalars(stmt.offset(offset).limit(limit)))
    return {"items": [_zone_out(item).model_dump() for item in items], "total": total, "limit": limit, "offset": offset}


@router.post("", response_model=ZoneOut, status_code=201, summary="Create a primary or secondary zone", description="Requires zones.write. The resulting BIND configuration is validated and reloaded transactionally.")
def create_zone(
    payload: ZoneCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    try:
        zone = service.create(payload, principal.username)
        write_audit(db, principal, get_client_ip(request), "CREATE_ZONE", "SUCCESS", zone=zone.name, new_value=payload.model_dump())
        return _zone_out(zone)
    except AppError as exc:
        write_audit(db, principal, get_client_ip(request), "CREATE_ZONE", "FAILED", zone=payload.name, new_value=payload.model_dump(), details=exc.details or exc.message)
        raise


@router.post("/reverse", response_model=ZoneOut, status_code=201, summary="Create an IPv4 reverse zone", description="Requires zones.write.")
def create_reverse_zone(
    payload: ReverseZoneRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    zone = ZoneService(db).create_reverse(payload.network, principal.username)
    write_audit(db, principal, get_client_ip(request), "CREATE_REVERSE_ZONE", "SUCCESS", zone=zone.name, new_value={"network": payload.network})
    return _zone_out(zone)


@router.post("/{zone_name}/copy", response_model=ZoneOut, status_code=201, summary="Copy a primary zone", description="Requires zones.write. The copy receives a fresh SOA serial and is validated before activation.")
def copy_zone(
    zone_name: str,
    new_name: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    source = service.get(zone_name)
    result = service.copy_zone(source, new_name, principal.username)
    write_audit(db, principal, get_client_ip(request), "COPY_ZONE", "SUCCESS", zone=result.name, old_value={"source": source.name}, new_value={"name": result.name})
    return _zone_out(result)


@router.get("/{zone_name}", response_model=ZoneOut, summary="Get zone", description="Requires zones.read.")
def get_zone(zone_name: str, db: Session = Depends(get_db), principal: Principal = Depends(require_permission("zones.read"))):
    return _zone_out(ZoneService(db).get(zone_name))


@router.get("/{zone_name}/revisions", response_model=list[ZoneRevisionOut], summary="List zone revisions", description="Requires zones.read.")
def list_zone_revisions(
    zone_name: str,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.read")),
):
    service = ZoneService(db)
    service.get(zone_name)
    return [ZoneRevisionOut.model_validate(item) for item in service.list_revisions(zone_name.rstrip(".").lower(), limit)]


@router.post("/{zone_name}/revisions/{revision_id}/restore", response_model=ZoneOut, summary="Restore a zone revision", description="Requires zones.write and the current zone version.")
def restore_zone_revision(
    zone_name: str,
    revision_id: int,
    payload: ZoneRestoreRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    if not zone.managed:
        raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones are read-only", 409)
    revision = db.get(ZoneRevision, revision_id)
    if revision is None or revision.zone_name != zone.name:
        raise AppError("REVISION_NOT_FOUND", "Zone revision not found", 404)
    old = {"version": zone.version, "serial": zone.serial}
    result = service.restore_revision(zone, revision, payload.version, principal.username)
    write_audit(
        db,
        principal,
        get_client_ip(request),
        "RESTORE_ZONE_REVISION",
        "SUCCESS",
        zone=zone.name,
        old_value=old,
        new_value={"revision_id": revision_id, "restored_version": revision.version, "current_version": result.version},
    )
    return _zone_out(result)


@router.post("/{zone_name}/preview", response_model=dict, summary="Preview zone settings", description="Requires zones.write. No files are modified.")
def preview_zone_settings(
    zone_name: str, payload: ZoneUpdate, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    if not zone.managed:
        raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones are read-only", 409)
    return {"diff": service.preview_zone(zone, payload)}


@router.put("/{zone_name}", response_model=ZoneOut, summary="Update zone settings", description="Requires zones.write and the current optimistic-lock version.")
def update_zone(
    zone_name: str,
    payload: ZoneUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    if not zone.managed:
        raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones must be synchronized or imported before editing", 409)
    old = {
        "enabled": zone.enabled,
        "default_ttl": zone.default_ttl,
        "soa_mname": zone.soa_mname,
        "soa_rname": zone.soa_rname,
        "primary_servers": list(zone.primary_servers or []),
        "allow_transfer": list(zone.allow_transfer or []),
        "also_notify": list(zone.also_notify or []),
        "tsig_key_name": zone.tsig_key_name,
        "version": zone.version,
    }
    result = service.update(zone, payload, principal.username)
    write_audit(db, principal, get_client_ip(request), "UPDATE_ZONE", "SUCCESS", zone=zone.name, old_value=old, new_value=payload.model_dump())
    return _zone_out(result)


@router.delete("/{zone_name}", status_code=204, summary="Delete a managed zone", description="Requires zones.write. A backup and revision are created before deletion.")
def delete_zone(
    zone_name: str,
    zone_version: int = Query(..., ge=1),
    request: Request = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    if not zone.managed:
        raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones are never deleted by the panel", 409)
    service.delete(zone, principal.username, zone_version)
    write_audit(db, principal, get_client_ip(request), "DELETE_ZONE", "SUCCESS", zone=zone_name)
    return Response(status_code=204)


@router.get("/{zone_name}/records", response_model=dict, summary="List records", description="Requires records.read. Secondary-zone records are not mirrored into the application database.")
def list_records(
    zone_name: str,
    q: str | None = None,
    record_type: str | None = Query(None, alias="type"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    page: int | None = Query(None, ge=1),
    page_size: int | None = Query(None, ge=1, le=500),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("records.read")),
):
    zone = ZoneService(db).get(zone_name)
    if page is not None or page_size is not None:
        effective_size = page_size or limit
        effective_page = page or 1
        limit, offset = effective_size, (effective_page - 1) * effective_size
    stmt = select(Record).where(Record.zone_id == zone.id)
    count_stmt = select(func.count(Record.id)).where(Record.zone_id == zone.id)
    if q:
        pattern = f"%{q.strip()}%"
        clause = or_(Record.name.ilike(pattern), Record.value.ilike(pattern))
        stmt = stmt.where(clause)
        count_stmt = count_stmt.where(clause)
    if record_type:
        stmt = stmt.where(Record.type == record_type.upper())
        count_stmt = count_stmt.where(Record.type == record_type.upper())
    items = list(db.scalars(stmt.order_by(Record.name, Record.type, Record.id).offset(offset).limit(limit)))
    return {
        "items": [RecordOut.model_validate(item).model_dump() for item in items],
        "total": db.scalar(count_stmt) or 0,
        "limit": limit,
        "offset": offset,
        "zone_version": zone.version,
        "zone_type": zone.zone_type,
    }


@router.post("/{zone_name}/records", response_model=RecordOut, status_code=201, summary="Create a DNS record", description="Requires records.write. Secondary zones are read-only.")
def create_record(
    zone_name: str,
    payload: RecordCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("records.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    if not zone.managed:
        raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones are read-only", 409)
    record = service.add_record(zone, payload, principal.username)
    write_audit(db, principal, get_client_ip(request), "CREATE_RECORD", "SUCCESS", zone=zone.name, record=f"{record.name} {record.type}", new_value=payload.model_dump())
    return RecordOut.model_validate(record)


@router.post("/{zone_name}/records/preview", response_model=dict, summary="Preview a record change", description="Requires records.write. No files are modified.")
def preview_record(
    zone_name: str,
    payload: RecordCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("records.write")),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    if zone.version != payload.zone_version:
        raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
    return {"diff": service.preview_record(zone, payload)}


@router.get("/{zone_name}/records/{record_id}", response_model=RecordOut, summary="Get record", description="Requires records.read.")
def get_record(zone_name: str, record_id: int, db: Session = Depends(get_db), principal: Principal = Depends(require_permission("records.read"))):
    zone = ZoneService(db).get(zone_name)
    record = db.scalar(select(Record).where(Record.id == record_id, Record.zone_id == zone.id))
    if record is None:
        raise AppError("RECORD_NOT_FOUND", "Record not found", 404)
    return RecordOut.model_validate(record)


@router.post("/{zone_name}/records/{record_id}/preview", response_model=dict, summary="Preview record update", description="Requires records.write. No files are modified.")
def preview_record_update(
    zone_name: str, record_id: int, payload: RecordUpdate, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("records.write")),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    record = db.scalar(select(Record).where(Record.id == record_id, Record.zone_id == zone.id))
    if record is None:
        raise AppError("RECORD_NOT_FOUND", "Record not found", 404)
    return {"diff": service.preview_record(zone, payload, record)}


@router.put("/{zone_name}/records/{record_id}", response_model=RecordOut, summary="Update record", description="Requires records.write. Secondary zones are read-only.")
def update_record(
    zone_name: str,
    record_id: int,
    payload: RecordUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("records.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    if not zone.managed:
        raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones are read-only", 409)
    record = db.scalar(select(Record).where(Record.id == record_id, Record.zone_id == zone.id))
    if record is None:
        raise AppError("RECORD_NOT_FOUND", "Record not found", 404)
    old = RecordOut.model_validate(record).model_dump()
    result = service.update_record(zone, record, payload, principal.username)
    write_audit(db, principal, get_client_ip(request), "UPDATE_RECORD", "SUCCESS", zone=zone.name, record=f"{result.name} {result.type}", old_value=old, new_value=payload.model_dump())
    return RecordOut.model_validate(result)


@router.delete("/{zone_name}/records/{record_id}", status_code=204, summary="Delete record", description="Requires records.write. zone_version is required for optimistic locking.")
def delete_record(
    zone_name: str,
    record_id: int,
    zone_version: int = Query(..., ge=1),
    request: Request = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("records.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    if not zone.managed:
        raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones are read-only", 409)
    record = db.scalar(select(Record).where(Record.id == record_id, Record.zone_id == zone.id))
    if record is None:
        raise AppError("RECORD_NOT_FOUND", "Record not found", 404)
    description = f"{record.name} {record.type} {record.value}"
    service.delete_record(zone, record, zone_version, principal.username)
    write_audit(db, principal, get_client_ip(request), "DELETE_RECORD", "SUCCESS", zone=zone.name, record=description)
    return Response(status_code=204)


@router.post("/{zone_name}/records/bulk", response_model=dict, summary="Bulk record operation", description="Requires records.write. Operations are validated as one zone transaction.")
def bulk_records(
    zone_name: str,
    payload: BulkRecordRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("records.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = ZoneService(db)
    zone = service.get(zone_name)
    service._require_primary(zone)
    if zone.version != payload.zone_version:
        raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
    records = list(db.scalars(select(Record).where(Record.zone_id == zone.id, Record.id.in_(payload.record_ids))))
    if len(records) != len(set(payload.record_ids)):
        raise AppError("RECORD_NOT_FOUND", "One or more records were not found", 404)
    if payload.operation == "export":
        return {"records": [RecordOut.model_validate(item).model_dump() for item in records], "zone_version": zone.version}
    if not zone.managed:
        raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones are read-only", 409)
    old = [RecordOut.model_validate(item).model_dump() for item in records]
    service._record_revision(zone, f"before BULK_{payload.operation.upper()}", principal.username)
    if payload.operation == "delete":
        for item in records:
            db.delete(item)
    else:
        for item in records:
            item.ttl = int(payload.ttl)
    from ..services.serials import next_soa_serial

    zone.serial = next_soa_serial(zone.serial)
    zone.version += 1
    db.flush()
    try:
        service._apply(zone, f"before BULK_{payload.operation.upper()} {zone.name}", principal.username)
        db.commit()
    except Exception:
        db.rollback()
        raise
    write_audit(db, principal, get_client_ip(request), f"BULK_{payload.operation.upper()}", "SUCCESS", zone=zone.name, old_value=old, new_value=payload.model_dump())
    return {"updated": len(records), "zone_version": zone.version}


@router.get("/{zone_name}/export", summary="Export a zone file", description="Requires zones.read. Secondary zones are transferred by BIND and do not have a panel-managed authoritative zone file.")
def export_zone(zone_name: str, db: Session = Depends(get_db), principal: Principal = Depends(require_permission("zones.read"))):
    zone = ZoneService(db).get(zone_name)
    if zone.zone_type == "secondary":
        raise AppError("SECONDARY_EXPORT_UNAVAILABLE", "Secondary zone content is owned by BIND transfer state, not the panel database", 409)
    text = render_zone(zone) if zone.managed else ZoneService(db).bind.read_zone(zone.source_path or "")
    return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="{zone.file_name}"'})


@router.get("/export/all/archive", summary="Export all primary zones", description="Requires zones.read. Returns a gzip-compressed tar archive containing standard BIND primary zone files.")
def export_all_zones(db: Session = Depends(get_db), principal: Principal = Depends(require_permission("zones.read"))):
    zones = list(db.scalars(select(Zone).where(Zone.zone_type != "secondary").order_by(Zone.name)))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for zone in zones:
            text = render_zone(zone) if zone.managed else ZoneService(db).bind.read_zone(zone.source_path or "")
            payload = text.encode("utf-8")
            info = tarfile.TarInfo(name=zone.file_name)
            info.size = len(payload)
            info.mode = 0o640
            tar.addfile(info, io.BytesIO(payload))
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/gzip", headers={"Content-Disposition": 'attachment; filename="chrislab-dns-zones.tar.gz"'})


@router.post("/import/file", response_model=ZoneOut, status_code=201, summary="Import a BIND zone file", description="Requires zones.write. The uploaded zone is parsed and validated before activation.")
async def import_zone_file(
    request: Request,
    zone_name: str,
    enabled: bool = True,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    raw = await file.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise AppError("UPLOAD_TOO_LARGE", "Zone file exceeds 2 MiB", 413)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppError("UPLOAD_ENCODING", "Zone file must be UTF-8 text", 422) from exc
    zone = ZoneService(db).import_zone(zone_name, text, principal.username, enabled)
    write_audit(db, principal, get_client_ip(request), "IMPORT_ZONE", "SUCCESS", zone=zone.name, new_value={"filename": file.filename})
    return _zone_out(zone)
