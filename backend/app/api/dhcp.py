from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import enforce_api_csrf, require_permission
from ..dhcp_schemas import DhcpGlobalUpdate, DhcpOptionCreate, DhcpPoolCreate, DhcpRawConfig, DhcpReservationCreate, DhcpSubnetCreate
from ..security import Principal, get_client_ip
from ..services.audit import write_audit
from ..services.dhcp import DhcpService

router = APIRouter(prefix="/dhcp", tags=["DHCP"])


@router.get("/status", summary="DHCPv4 and DHCPv6 service status")
def status(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.read")),
):
    service = DhcpService(db)
    result = {}
    for family in (4, 6):
        try:
            result[str(family)] = service.status(family)
        except Exception as exc:
            result[str(family)] = {"family": family, "active": False, "error": str(exc)}
    return result


@router.get("/{family}/config", summary="Read DHCP draft configuration")
def get_config(
    family: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.read")),
):
    return DhcpService(db).load_draft(family)


@router.put("/{family}/config", summary="Replace complete Kea DHCP draft")
def replace_config(
    family: int,
    payload: DhcpRawConfig,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    old = DhcpService(db).load_draft(family)
    result = DhcpService(db).save_draft(family, payload.config)
    write_audit(db, principal, get_client_ip(request), "DHCP_SAVE_CONFIG", "SUCCESS", old_value=old, new_value=result, details=f"DHCPv{family} draft")
    return result


@router.put("/{family}/global", summary="Update common DHCP server settings")
def update_global(
    family: int,
    payload: DhcpGlobalUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).set_global(family, payload)
    write_audit(db, principal, get_client_ip(request), "DHCP_UPDATE_GLOBAL", "SUCCESS", new_value=payload.model_dump(), details=f"DHCPv{family}")
    return result


@router.post("/{family}/subnets", status_code=201, summary="Create DHCP subnet")
def create_subnet(
    family: int,
    payload: DhcpSubnetCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).add_subnet(family, payload)
    write_audit(db, principal, get_client_ip(request), "DHCP_CREATE_SUBNET", "SUCCESS", new_value=payload.model_dump(), details=f"DHCPv{family}")
    return result


@router.delete("/{family}/subnets/{subnet_id}", summary="Delete DHCP subnet")
def delete_subnet(
    family: int,
    subnet_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).delete_subnet(family, subnet_id)
    write_audit(db, principal, get_client_ip(request), "DHCP_DELETE_SUBNET", "SUCCESS", details=f"DHCPv{family} subnet id={subnet_id}")
    return result


@router.post("/{family}/subnets/{subnet_id}/pools", status_code=201, summary="Add DHCP pool")
def add_pool(
    family: int,
    subnet_id: int,
    payload: DhcpPoolCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).add_pool(family, subnet_id, payload)
    write_audit(db, principal, get_client_ip(request), "DHCP_ADD_POOL", "SUCCESS", new_value=payload.model_dump(), details=f"DHCPv{family} subnet id={subnet_id}")
    return result


@router.delete("/{family}/subnets/{subnet_id}/pools/{pool_index}", summary="Delete DHCP pool")
def delete_pool(
    family: int,
    subnet_id: int,
    pool_index: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).delete_pool(family, subnet_id, pool_index)
    write_audit(db, principal, get_client_ip(request), "DHCP_DELETE_POOL", "SUCCESS", details=f"DHCPv{family} subnet id={subnet_id} pool={pool_index}")
    return result


@router.post("/{family}/subnets/{subnet_id}/reservations", status_code=201, summary="Create DHCP reservation")
def add_reservation(
    family: int,
    subnet_id: int,
    payload: DhcpReservationCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).add_reservation(family, subnet_id, payload)
    write_audit(db, principal, get_client_ip(request), "DHCP_ADD_RESERVATION", "SUCCESS", new_value=payload.model_dump(), details=f"DHCPv{family} subnet id={subnet_id}")
    return result


@router.delete("/{family}/subnets/{subnet_id}/reservations/{reservation_index}", summary="Delete DHCP reservation")
def delete_reservation(
    family: int,
    subnet_id: int,
    reservation_index: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).delete_reservation(family, subnet_id, reservation_index)
    write_audit(db, principal, get_client_ip(request), "DHCP_DELETE_RESERVATION", "SUCCESS", details=f"DHCPv{family} subnet id={subnet_id} reservation={reservation_index}")
    return result


@router.post("/{family}/options", status_code=201, summary="Add global DHCP option")
def add_global_option(
    family: int,
    payload: DhcpOptionCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).add_option(family, payload)
    write_audit(db, principal, get_client_ip(request), "DHCP_ADD_OPTION", "SUCCESS", new_value=payload.model_dump(), details=f"DHCPv{family} global")
    return result


@router.delete("/{family}/options/{option_index}", summary="Delete global DHCP option")
def delete_global_option(
    family: int,
    option_index: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).delete_option(family, option_index)
    write_audit(db, principal, get_client_ip(request), "DHCP_DELETE_OPTION", "SUCCESS", details=f"DHCPv{family} global option={option_index}")
    return result


@router.post("/{family}/subnets/{subnet_id}/options", status_code=201, summary="Add subnet DHCP option")
def add_subnet_option(
    family: int,
    subnet_id: int,
    payload: DhcpOptionCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).add_option(family, payload, subnet_id=subnet_id)
    write_audit(db, principal, get_client_ip(request), "DHCP_ADD_OPTION", "SUCCESS", new_value=payload.model_dump(), details=f"DHCPv{family} subnet id={subnet_id}")
    return result


@router.delete("/{family}/subnets/{subnet_id}/options/{option_index}", summary="Delete subnet DHCP option")
def delete_subnet_option(
    family: int,
    subnet_id: int,
    option_index: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).delete_option(family, option_index, subnet_id=subnet_id)
    write_audit(db, principal, get_client_ip(request), "DHCP_DELETE_OPTION", "SUCCESS", details=f"DHCPv{family} subnet id={subnet_id} option={option_index}")
    return result


@router.post("/{family}/validate", summary="Validate DHCP draft with Kea")
def validate(
    family: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).validate_draft(family)
    write_audit(db, principal, get_client_ip(request), "DHCP_VALIDATE", "SUCCESS", details=f"DHCPv{family}: {result[:500]}")
    return {"status": "valid", "details": result}


@router.post("/{family}/apply", summary="Validate and atomically apply DHCP draft")
def apply(
    family: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).apply_draft(family)
    write_audit(db, principal, get_client_ip(request), "DHCP_APPLY", "SUCCESS", details=f"DHCPv{family}: {result[:500]}")
    return {"status": "applied", "details": result}


@router.post("/{family}/import", summary="Import active Kea configuration into the Web UI draft")
def import_active(
    family: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).import_active(family)
    write_audit(db, principal, get_client_ip(request), "DHCP_IMPORT", "SUCCESS", details=f"DHCPv{family}")
    return result


@router.post("/{family}/service/{action}", summary="Control DHCP service")
def service_action(
    family: int,
    action: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.manage")),
    _: Principal = Depends(enforce_api_csrf),
):
    result = DhcpService(db).service_action(family, action)
    write_audit(db, principal, get_client_ip(request), "DHCP_SERVICE", "SUCCESS", details=f"DHCPv{family} {action}")
    return {"status": "ok", "details": result}


@router.get("/{family}/leases", summary="Read recent Kea memfile leases")
def leases(
    family: int,
    limit: int = Query(default=250, ge=1, le=2000),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.read")),
):
    return DhcpService(db).leases(family, limit)


@router.get("/{family}/logs", summary="Read DHCP service logs")
def logs(
    family: int,
    lines: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dhcp.read")),
):
    return {"family": family, "logs": DhcpService(db).logs(family, lines)}
