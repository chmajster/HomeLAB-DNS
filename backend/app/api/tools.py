from __future__ import annotations

import time

import dns.exception
import dns.resolver
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import enforce_api_csrf, require_permission
from ..schemas import LookupRequest
from ..security import Principal
from ..services.dns_tools import lookup
from ..services.sync import SyncService

router = APIRouter(tags=["Tools"])


@router.post("/tools/lookup", summary="Perform a DNS lookup", description="Requires tools.lookup.")
def dns_lookup(payload: LookupRequest, principal: Principal = Depends(require_permission("tools.lookup"))):
    return lookup(payload.name, payload.type, payload.server)


@router.get("/sync", summary="Compare BIND files with panel database", description="Requires zones.read. No files are modified.")
def sync_compare(db: Session = Depends(get_db), principal: Principal = Depends(require_permission("zones.read"))):
    return SyncService(db).compare()


@router.post("/sync/import", summary="Import missing BIND zones into the database", description="Requires zones.write. Existing files are not modified and imported zones remain externally managed/read-only.")
def sync_import(
    names: list[str] | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    imported = SyncService(db).import_missing(names)
    return {"imported": imported, "count": len(imported)}


@router.post("/zones/{zone_name}/test", summary="Test a zone through the local DNS server", description="Requires tools.lookup.")
def test_zone_dns(zone_name: str, payload: LookupRequest, principal: Principal = Depends(require_permission("tools.lookup"))):
    return lookup(payload.name or zone_name, payload.type, payload.server or "127.0.0.1")
