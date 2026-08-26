from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .. import __version__
from ..database import get_db
from ..dependencies import require_permission
from ..models import AppState, AuditLog, Backup, Record, Zone
from ..security import Principal
from ..services.bind import BindService
from .admin import audit_router, backups_router, tokens_router, users_router
from .bindops import router as bind_router
from .dhcp import router as dhcp_router
from .dnssec import router as dnssec_router
from .platform import router as platform_router
from .tools import router as tools_router
from .zones import router as zones_router

api_router = APIRouter(prefix="/api/v1")


@api_router.get("/version", tags=["System"], summary="Application version")
def version():
    return {"version": __version__}


@api_router.get("/health", tags=["System"], summary="Health check")
def health(db: Session = Depends(get_db)):
    database = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        database = "unhealthy"
    bind = "unknown"
    configuration = "unknown"
    try:
        status = BindService().status()
        bind = "running" if status.get("active") else "stopped"
        BindService().validate_config()
        configuration = "valid"
    except Exception:
        if bind == "unknown":
            bind = "unavailable"
        configuration = "invalid"
    overall = "healthy" if database == "healthy" and bind == "running" and configuration == "valid" else "degraded"
    return {"status": overall, "bind": bind, "database": database, "configuration": configuration}


@api_router.get("/search", tags=["System"], summary="Global DNS search", description="Search zones, record owners, values, IP addresses and hostnames. Requires zones.read and records.read.")
def global_search(
    q: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("records.read")),
):
    query = q.strip()
    if not query:
        return {"zones": [], "records": []}
    safe_limit = max(1, min(int(limit), 200))
    pattern = f"%{query}%"
    zones = list(db.scalars(select(Zone).where(Zone.name.ilike(pattern)).order_by(Zone.name).limit(safe_limit)))
    records = list(db.execute(
        select(Record, Zone).join(Zone, Record.zone_id == Zone.id)
        .where((Zone.name.ilike(pattern)) | (Record.name.ilike(pattern)) | (Record.value.ilike(pattern)) | (Record.type.ilike(pattern)))
        .order_by(Zone.name, Record.name).limit(safe_limit)
    ))
    return {
        "zones": [{"name": z.name, "enabled": z.enabled, "managed": z.managed, "serial": z.serial, "zone_type": z.zone_type} for z in zones],
        "records": [{"zone": z.name, "id": r.id, "name": r.name, "type": r.type, "value": r.value, "ttl": r.ttl} for r, z in records],
    }


@api_router.get("/status", tags=["System"], summary="Dashboard status")
def status(db: Session = Depends(get_db), principal: Principal = Depends(require_permission("zones.read"))):
    bind_status: dict[str, object]
    config_status = "invalid"
    try:
        bind_status = BindService().status()
        BindService().validate_config()
        config_status = "valid"
    except Exception as exc:
        bind_status = {"active": False, "error": str(exc)}
    last_change = db.scalar(select(func.max(AuditLog.timestamp)))
    last_backup = db.scalar(select(func.max(Backup.created_at)))
    last_reload = db.get(AppState, "last_reload")
    return {
        "bind": bind_status,
        "api": "healthy",
        "configuration": config_status,
        "zones": db.scalar(select(func.count(Zone.id))) or 0,
        "records": db.scalar(select(func.count(Record.id))) or 0,
        "last_change": last_change,
        "last_reload": last_reload.value if last_reload else None,
        "last_backup": last_backup,
    }


api_router.include_router(zones_router)
api_router.include_router(dnssec_router)
api_router.include_router(bind_router)
api_router.include_router(platform_router)
api_router.include_router(dhcp_router)
api_router.include_router(backups_router)
api_router.include_router(audit_router)
api_router.include_router(tokens_router)
api_router.include_router(users_router)
api_router.include_router(tools_router)
