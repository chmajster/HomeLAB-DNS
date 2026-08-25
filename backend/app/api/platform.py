from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import enforce_api_csrf, require_permission
from ..errors import AppError
from ..models import DnsServer, TsigKey, Zone
from ..schemas import DnsServerCreate, DnsServerOut, DnsServerUpdate, TsigKeyCreate, TsigKeyCreated, TsigKeyOut
from ..security import Principal, get_client_ip
from ..services.audit import write_audit
from ..services.platform import DnsPlatformService
from ..services.zones import ZoneService

router = APIRouter(tags=["DNS Platform"])


def _refresh_managed_config(db: Session, username: str, reason: str) -> None:
    carrier = db.scalar(select(Zone).where(Zone.managed.is_(True)).order_by(Zone.id).limit(1))
    if carrier is None:
        return
    ZoneService(db)._apply(carrier, reason, username)
    db.commit()


@router.get("/servers", response_model=list[DnsServerOut], summary="List DNS servers", description="Requires zones.read.")
def list_servers(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.read")),
):
    return [DnsServerOut.model_validate(row) for row in DnsPlatformService(db).list_servers()]


@router.post("/servers", response_model=DnsServerOut, status_code=201, summary="Register a DNS server", description="Requires settings.manage.")
def create_server(
    payload: DnsServerCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("settings.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    row = DnsPlatformService(db).create_server(payload)
    write_audit(db, principal, get_client_ip(request), "CREATE_DNS_SERVER", "SUCCESS", new_value=payload.model_dump())
    return DnsServerOut.model_validate(row)


@router.put("/servers/{server_id}", response_model=DnsServerOut, summary="Update a DNS server", description="Requires settings.manage.")
def update_server(
    server_id: int,
    payload: DnsServerUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("settings.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    row = db.get(DnsServer, server_id)
    if row is None:
        raise AppError("DNS_SERVER_NOT_FOUND", "DNS server not found", 404)
    old = DnsServerOut.model_validate(row).model_dump()
    result = DnsPlatformService(db).update_server(row, payload)
    write_audit(db, principal, get_client_ip(request), "UPDATE_DNS_SERVER", "SUCCESS", old_value=old, new_value=payload.model_dump(exclude_unset=True))
    return DnsServerOut.model_validate(result)


@router.delete("/servers/{server_id}", status_code=204, summary="Delete a DNS server", description="Requires settings.manage.")
def delete_server(
    server_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("settings.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    row = db.get(DnsServer, server_id)
    if row is None:
        raise AppError("DNS_SERVER_NOT_FOUND", "DNS server not found", 404)
    name = row.name
    DnsPlatformService(db).delete_server(row)
    write_audit(db, principal, get_client_ip(request), "DELETE_DNS_SERVER", "SUCCESS", old_value={"name": name})
    return Response(status_code=204)


@router.post("/servers/{server_id}/check", response_model=dict, summary="Check DNS server port 53", description="Requires zones.read.")
def check_server(
    server_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.read")),
    _: Principal = Depends(enforce_api_csrf),
):
    row = db.get(DnsServer, server_id)
    if row is None:
        raise AppError("DNS_SERVER_NOT_FOUND", "DNS server not found", 404)
    return DnsPlatformService(db).check_server(row)


@router.get("/tsig-keys", response_model=list[TsigKeyOut], summary="List TSIG keys", description="Requires settings.manage. Secrets are never returned by list operations.")
def list_tsig_keys(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("settings.manage")),
):
    return [TsigKeyOut.model_validate(row) for row in DnsPlatformService(db).list_tsig_keys()]


@router.post("/tsig-keys", response_model=TsigKeyCreated, status_code=201, summary="Create a TSIG key", description="Requires settings.manage. The plaintext secret is returned exactly once.")
def create_tsig_key(
    payload: TsigKeyCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("settings.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    row, secret = DnsPlatformService(db).create_tsig_key(payload)
    write_audit(db, principal, get_client_ip(request), "CREATE_TSIG_KEY", "SUCCESS", new_value={"name": row.name, "algorithm": row.algorithm})
    return TsigKeyCreated(id=row.id, name=row.name, algorithm=row.algorithm, created_at=row.created_at, secret=secret)


@router.post("/tsig-keys/{key_id}/rotate", response_model=TsigKeyCreated, summary="Rotate a TSIG key", description="Requires settings.manage. The new plaintext secret is returned exactly once and active managed BIND configuration is refreshed.")
def rotate_tsig_key(
    key_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("settings.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    row = db.get(TsigKey, key_id)
    if row is None:
        raise AppError("TSIG_KEY_NOT_FOUND", "TSIG key not found", 404)
    secret = DnsPlatformService(db).rotate_tsig_key(row)
    _refresh_managed_config(db, principal.username, f"before ROTATE_TSIG {row.name}")
    write_audit(db, principal, get_client_ip(request), "ROTATE_TSIG_KEY", "SUCCESS", new_value={"name": row.name})
    return TsigKeyCreated(id=row.id, name=row.name, algorithm=row.algorithm, created_at=row.created_at, secret=secret)


@router.delete("/tsig-keys/{key_id}", status_code=204, summary="Delete an unused TSIG key", description="Requires settings.manage.")
def delete_tsig_key(
    key_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("settings.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    row = db.get(TsigKey, key_id)
    if row is None:
        raise AppError("TSIG_KEY_NOT_FOUND", "TSIG key not found", 404)
    name = row.name
    DnsPlatformService(db).delete_tsig_key(row)
    _refresh_managed_config(db, principal.username, f"before DELETE_TSIG {name}")
    write_audit(db, principal, get_client_ip(request), "DELETE_TSIG_KEY", "SUCCESS", old_value={"name": name})
    return Response(status_code=204)
