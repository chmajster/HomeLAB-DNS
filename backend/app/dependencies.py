from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .database import get_db
from .errors import AppError
from .security import Principal, authenticate_request, ensure_csrf


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    return authenticate_request(request, db)


def require_permission(permission: str) -> Callable:
    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if permission not in principal.permissions:
            raise AppError("FORBIDDEN", f"Permission required: {permission}", 403)
        return principal
    return dependency


def enforce_api_csrf(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
    if principal.auth_type == "session" and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        ensure_csrf(request, request.headers.get("x-csrf-token"))
    return principal
