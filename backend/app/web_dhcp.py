from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .database import get_db
from .dhcp_schemas import DhcpGlobalUpdate, DhcpOptionCreate, DhcpPoolCreate, DhcpReservationCreate, DhcpSubnetCreate
from .errors import AppError
from .security import ensure_csrf
from .services.dhcp import DhcpService
from .services.dhcp_runtime import DhcpRuntimeOps
from .web_platform import _context, _permissions, _user

PROJECT_ROOT = Path(__file__).resolve().parents[2]
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "frontend" / "templates"))
router = APIRouter(include_in_schema=False)


def _family(value: int) -> int:
    if value not in {4, 6}:
        raise AppError("INVALID_DHCP_FAMILY", "DHCP family must be 4 or 6", 422)
    return value


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


def _require_manage(request: Request, db: Session):
    user = _user(request, db)
    if "dhcp.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: dhcp.manage", 403)
    return user


def _safe_runtime(service: DhcpService, family: int) -> tuple[dict, list[dict], str, str | None]:
    error = None
    try:
        status = service.status(family)
    except Exception as exc:
        status = {"family": family, "active": False, "enabled": False, "error": str(exc)}
        error = str(exc)
    try:
        leases = service.leases(family, 250)
    except Exception as exc:
        leases = []
        error = error or str(exc)
    try:
        logs = service.logs(family, 80)
    except Exception as exc:
        logs = str(exc)
        error = error or str(exc)
    return status, leases, logs, error


def _safe_backups(runtime: DhcpRuntimeOps, family: int) -> tuple[list[dict], str | None]:
    try:
        return runtime.backups(family), None
    except Exception as exc:
        return [], str(exc)


@router.get("/dhcp", response_class=HTMLResponse)
def dhcp_page(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if "dhcp.read" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: dhcp.read", 403)
    service = DhcpService(db)
    runtime = DhcpRuntimeOps(service)
    config4 = service.load_draft(4)
    config6 = service.load_draft(6)
    status4, leases4, logs4, error4 = _safe_runtime(service, 4)
    status6, leases6, logs6, error6 = _safe_runtime(service, 6)
    backups4, backup_error4 = _safe_backups(runtime, 4)
    backups6, backup_error6 = _safe_backups(runtime, 6)
    return templates.TemplateResponse(
        request,
        "dhcp.html",
        _context(
            request,
            db,
            config4=config4["Dhcp4"],
            config6=config6["Dhcp6"],
            raw4=json.dumps(config4, indent=2, ensure_ascii=False),
            raw6=json.dumps(config6, indent=2, ensure_ascii=False),
            status4=status4,
            status6=status6,
            leases4=leases4,
            leases6=leases6,
            logs4=logs4,
            logs6=logs6,
            error4=error4,
            error6=error6,
            backups4=backups4,
            backups6=backups6,
            backup_error4=backup_error4,
            backup_error6=backup_error6,
            interfaces=runtime.interfaces(),
            can_manage="dhcp.manage" in _permissions(user),
            message=request.query_params.get("message"),
        ),
    )


@router.post("/dhcp/{family}/global")
def save_global(
    family: int,
    request: Request,
    interfaces: str = Form(""),
    valid_lifetime: int = Form(3600),
    renew_timer: int = Form(900),
    rebind_timer: int = Form(1800),
    preferred_lifetime: int | None = Form(None),
    authoritative: str | None = Form(None),
    dns_servers: str = Form(""),
    domain_name: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _family(family)
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).set_global(
        family,
        DhcpGlobalUpdate(
            interfaces=_csv(interfaces),
            valid_lifetime=valid_lifetime,
            renew_timer=renew_timer,
            rebind_timer=rebind_timer,
            preferred_lifetime=preferred_lifetime,
            authoritative=authoritative is not None,
            dns_servers=_csv(dns_servers),
            domain_name=domain_name or None,
        ),
    )
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+global+settings+saved", status_code=303)


@router.post("/dhcp/{family}/subnets")
def create_subnet(
    family: int,
    request: Request,
    subnet: str = Form(...),
    interface: str = Form(""),
    pool: str = Form(""),
    routers: str = Form(""),
    dns_servers: str = Form(""),
    domain_name: str = Form(""),
    valid_lifetime: int | None = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _family(family)
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).add_subnet(
        family,
        DhcpSubnetCreate(
            subnet=subnet,
            interface=interface or None,
            pool=pool or None,
            routers=_csv(routers),
            dns_servers=_csv(dns_servers),
            domain_name=domain_name or None,
            valid_lifetime=valid_lifetime,
        ),
    )
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+subnet+created", status_code=303)


@router.post("/dhcp/{family}/subnets/{subnet_id}/delete")
def delete_subnet(family: int, subnet_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    _family(family)
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).delete_subnet(family, subnet_id)
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+subnet+deleted", status_code=303)


@router.post("/dhcp/{family}/subnets/{subnet_id}/pools")
def add_pool(
    family: int,
    subnet_id: int,
    request: Request,
    pool: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).add_pool(_family(family), subnet_id, DhcpPoolCreate(pool=pool))
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+pool+added", status_code=303)


@router.post("/dhcp/{family}/subnets/{subnet_id}/pools/{pool_index}/delete")
def delete_pool(family: int, subnet_id: int, pool_index: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).delete_pool(_family(family), subnet_id, pool_index)
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+pool+deleted", status_code=303)


@router.post("/dhcp/{family}/subnets/{subnet_id}/reservations")
def add_reservation(
    family: int,
    subnet_id: int,
    request: Request,
    identifier_type: str = Form(...),
    identifier: str = Form(...),
    address: str = Form(...),
    hostname: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).add_reservation(
        _family(family),
        subnet_id,
        DhcpReservationCreate(identifier_type=identifier_type, identifier=identifier, address=address, hostname=hostname or None),
    )
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+reservation+added", status_code=303)


@router.post("/dhcp/{family}/subnets/{subnet_id}/reservations/{reservation_index}/delete")
def delete_reservation(family: int, subnet_id: int, reservation_index: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).delete_reservation(_family(family), subnet_id, reservation_index)
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+reservation+deleted", status_code=303)


@router.post("/dhcp/{family}/options")
def add_global_option(
    family: int,
    request: Request,
    name: str = Form(""),
    code: int | None = Form(None),
    data: str = Form(...),
    space: str = Form(""),
    csv_format: str | None = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).add_option(
        _family(family),
        DhcpOptionCreate(name=name or None, code=code, data=data, space=space or None, csv_format=csv_format is not None),
    )
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+option+added", status_code=303)


@router.post("/dhcp/{family}/options/{option_index}/delete")
def delete_global_option(family: int, option_index: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).delete_option(_family(family), option_index)
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+option+deleted", status_code=303)


@router.post("/dhcp/{family}/subnets/{subnet_id}/options")
def add_subnet_option(
    family: int,
    subnet_id: int,
    request: Request,
    name: str = Form(""),
    code: int | None = Form(None),
    data: str = Form(...),
    space: str = Form(""),
    csv_format: str | None = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).add_option(
        _family(family),
        DhcpOptionCreate(name=name or None, code=code, data=data, space=space or None, csv_format=csv_format is not None),
        subnet_id=subnet_id,
    )
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+subnet+option+added", status_code=303)


@router.post("/dhcp/{family}/subnets/{subnet_id}/options/{option_index}/delete")
def delete_subnet_option(family: int, subnet_id: int, option_index: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).delete_option(_family(family), option_index, subnet_id=subnet_id)
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+subnet+option+deleted", status_code=303)


@router.post("/dhcp/{family}/advanced")
def save_advanced(
    family: int,
    request: Request,
    config_json: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).save_raw(_family(family), config_json)
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+advanced+JSON+saved", status_code=303)


@router.post("/dhcp/{family}/validate")
def validate_dhcp(family: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).validate_draft(_family(family))
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+configuration+valid", status_code=303)


@router.post("/dhcp/{family}/apply")
def apply_dhcp(family: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).apply_draft(_family(family))
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+configuration+applied", status_code=303)


@router.post("/dhcp/{family}/import")
def import_dhcp(family: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).import_active(_family(family))
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+active+configuration+imported", status_code=303)


@router.post("/dhcp/{family}/restore")
def restore_dhcp(
    family: int,
    request: Request,
    backup_name: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    service = DhcpService(db)
    DhcpRuntimeOps(service).restore(_family(family), backup_name)
    service.import_active(family)
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+backup+restored", status_code=303)


@router.post("/dhcp/{family}/service")
def control_service(
    family: int,
    request: Request,
    action: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_manage(request, db)
    ensure_csrf(request, csrf_token)
    DhcpService(db).service_action(_family(family), action)
    return RedirectResponse(f"/dhcp?message=DHCPv{family}+service+{action}", status_code=303)
