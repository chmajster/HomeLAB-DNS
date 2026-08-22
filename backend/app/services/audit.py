from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditLog
from ..security import Principal


def _dump(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def write_audit(
    db: Session,
    principal: Principal | None,
    ip: str,
    action: str,
    result: str,
    zone: str | None = None,
    record: str | None = None,
    old_value: Any = None,
    new_value: Any = None,
    details: str | None = None,
) -> AuditLog:
    row = AuditLog(
        user_id=principal.user_id if principal else None,
        username=principal.username if principal else "system",
        ip=ip,
        action=action,
        zone=zone,
        record=record,
        old_value=_dump(old_value),
        new_value=_dump(new_value),
        result=result,
        details=details,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
