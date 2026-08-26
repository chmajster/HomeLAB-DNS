from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import enforce_api_csrf, require_permission
from ..security import Principal, get_client_ip
from ..services.audit import write_audit
from ..services.dnssec import DnssecService
from ..services.zones import ZoneService

router = APIRouter(prefix="/zones", tags=["DNSSEC"])


class DnssecPolicyUpdate(BaseModel):
    version: Annotated[int, Field(ge=1)]
    policy: Literal["none", "default", "insecure"]


@router.get(
    "/{zone_name}/dnssec",
    response_model=dict,
    summary="Get DNSSEC state and DS records",
    description="Requires zones.read. DS records are derived from the active local DNSKEY RRset.",
)
def dnssec_status(
    zone_name: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.read")),
):
    zone = ZoneService(db).get(zone_name)
    return DnssecService(db).status(zone)


@router.put(
    "/{zone_name}/dnssec",
    response_model=dict,
    summary="Change DNSSEC policy",
    description="Requires zones.write and the current zone version. The BIND configuration is validated and applied transactionally.",
)
def update_dnssec_policy(
    zone_name: str,
    payload: DnssecPolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("zones.write")),
    _: Principal = Depends(enforce_api_csrf),
):
    zone = ZoneService(db).get(zone_name)
    old_policy = zone.dnssec_policy or "none"
    try:
        result = DnssecService(db).set_policy(zone, payload.policy, payload.version, principal.username)
        status = DnssecService(db).status(result)
        write_audit(
            db,
            principal,
            get_client_ip(request),
            "UPDATE_DNSSEC_POLICY",
            "SUCCESS",
            zone=result.name,
            old_value={"policy": old_policy, "version": payload.version},
            new_value={"policy": result.dnssec_policy, "version": result.version},
        )
        return status | {"version": result.version}
    except Exception as exc:
        write_audit(
            db,
            principal,
            get_client_ip(request),
            "UPDATE_DNSSEC_POLICY",
            "FAILED",
            zone=zone.name,
            old_value={"policy": old_policy, "version": payload.version},
            new_value={"policy": payload.policy},
            details=str(exc),
        )
        raise
