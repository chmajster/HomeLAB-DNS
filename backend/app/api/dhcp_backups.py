from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import enforce_api_csrf, require_permission
from ..security import Principal, get_client_ip
from ..services.audit import write_audit
from ..services.dhcp import DhcpService
from ..services.dhcp_runtime import DhcpRuntimeOps

router = APIRouter(prefix="/dhcp", tags=["DHCP"])


@router.get("/{family}/backups", summary="List Kea DHCP configuration backups")
def list_backups(
    family: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.read")),
):
    return DhcpRuntimeOps(DhcpService(db)).backups(family)


@router.post("/{family}/backups/{backup_name}/restore", summary="Restore a Kea DHCP configuration backup")
def restore_backup(
    family: int,
    backup_name: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    service = DhcpService(db)
    result = DhcpRuntimeOps(service).restore(family, backup_name)
    service.import_active(family)
    write_audit(
        db,
        principal,
        get_client_ip(request),
        "DHCP_RESTORE_BACKUP",
        "SUCCESS",
        details=f"DHCPv{family} backup={backup_name}",
    )
    return {"status": "restored", "details": result, "backup": backup_name}
