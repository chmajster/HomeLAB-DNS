from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import enforce_api_csrf, require_permission
from ..models import AppState, Record, Zone
from ..security import Principal, get_client_ip
from ..services.audit import write_audit
from ..services.bind import BindService

router = APIRouter(prefix="/bind", tags=["BIND9"])


@router.post("/validate", summary="Validate BIND configuration", description="Requires bind.reload. No reload is performed.")
def validate_bind(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("bind.reload")),
    _: Principal = Depends(enforce_api_csrf),
):
    output = BindService().validate_config()
    write_audit(db, principal, get_client_ip(request), "VALIDATE_CONFIG", "SUCCESS", details=output)
    return {"valid": True, "output": output}


@router.post("/reload", summary="Validate and reload BIND9", description="Requires bind.reload. Validation always runs before reload.")
def reload_bind(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("bind.reload")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = BindService()
    service.reload()
    db.merge(AppState(key="last_reload", value=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()))
    db.commit()
    write_audit(db, principal, get_client_ip(request), "RELOAD_BIND", "SUCCESS")
    return {"status": "reloaded"}


@router.post("/restart", summary="Validate and restart BIND9", description="Requires bind.restart. Web UI requires an explicit confirmation before invoking this endpoint.")
def restart_bind(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("bind.restart")),
    _: Principal = Depends(enforce_api_csrf),
):
    BindService().restart()
    write_audit(db, principal, get_client_ip(request), "RESTART_BIND", "SUCCESS")
    return {"status": "restarted"}


@router.get("/logs", summary="Read BIND9 journal logs", description="Requires logs.read. Arguments are bounded and mapped to a fixed helper command.")
def bind_logs(
    lines: int = Query(200, ge=1, le=2000),
    since_minutes: int = Query(60, ge=1, le=10080),
    level: str = Query("info", pattern=r"^(debug|info|notice|warning|err|crit)$"),
    offset: int = Query(0, ge=0, le=10000),
    page: int | None = Query(None, ge=1),
    page_size: int | None = Query(None, ge=1, le=2000),
    principal: Principal = Depends(require_permission("logs.read")),
):
    if page is not None or page_size is not None:
        effective_size = page_size or lines
        effective_page = page or 1
        lines, offset = effective_size, (effective_page - 1) * effective_size
    fetch_lines = min(lines + offset, 12000)
    raw = BindService().logs(fetch_lines, since_minutes, level).splitlines()
    selected = raw[offset:offset + lines]
    return {
        "logs": "\n".join(selected), "lines": lines, "offset": offset,
        "page": (offset // lines) + 1 if lines else 1, "page_size": lines,
        "since_minutes": since_minutes, "level": level,
    }
