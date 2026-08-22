from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..dependencies import enforce_api_csrf, require_permission
from ..errors import AppError
from ..models import ApiToken, AuditLog, Backup, User
from ..permissions import ALL_PERMISSIONS
from ..schemas import BackupCreate, PasswordChange, TokenCreate, TokenCreated, UserCreate, UserUpdate
from ..security import Principal, create_api_token, get_client_ip, hash_password, token_digest
from ..services.audit import write_audit
from ..services.backup import BackupService

backups_router = APIRouter(prefix="/backups", tags=["Backups"])
audit_router = APIRouter(prefix="/audit", tags=["Audit"])
tokens_router = APIRouter(prefix="/tokens", tags=["API Tokens"])
users_router = APIRouter(prefix="/users", tags=["Users"])


@backups_router.get("", summary="List backups", description="Requires backups.read.")
def list_backups(
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    db: Session = Depends(get_db), principal: Principal = Depends(require_permission("backups.read")),
):
    total = db.scalar(select(func.count(Backup.id))) or 0
    rows = list(db.scalars(select(Backup).order_by(Backup.created_at.desc()).offset(offset).limit(limit)))
    return {"items": [{"id": x.id, "filename": x.filename, "reason": x.reason, "created_by": x.created_by, "created_at": x.created_at, "size_bytes": x.size_bytes} for x in rows], "total": total, "limit": limit, "offset": offset}


@backups_router.post("", status_code=201, summary="Create backup", description="Requires backups.create.")
def create_backup(
    payload: BackupCreate, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("backups.create")), _: Principal = Depends(enforce_api_csrf),
):
    row = BackupService(db).create(payload.reason, principal.username)
    db.commit()
    db.refresh(row)
    write_audit(db, principal, get_client_ip(request), "CREATE_BACKUP", "SUCCESS", new_value={"backup_id": row.id, "reason": payload.reason})
    return {"id": row.id, "filename": row.filename, "size_bytes": row.size_bytes, "created_at": row.created_at}


@backups_router.get("/{backup_id}/download", summary="Download backup", description="Requires backups.read.")
def download_backup(backup_id: int, db: Session = Depends(get_db), principal: Principal = Depends(require_permission("backups.read"))):
    row = db.get(Backup, backup_id)
    if row is None:
        raise AppError("BACKUP_NOT_FOUND", "Backup not found", 404)
    path = (get_settings().backup_dir / row.filename).resolve()
    if get_settings().backup_dir.resolve() not in path.parents or not path.is_file():
        raise AppError("BACKUP_NOT_FOUND", "Backup file not found", 404)
    return FileResponse(path, media_type="application/gzip", filename=row.filename)


@backups_router.post("/{backup_id}/restore", summary="Restore backup", description="Requires backups.restore. BIND is validated and automatically rolled back if restore fails.")
def restore_backup(
    backup_id: int, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("backups.restore")), _: Principal = Depends(enforce_api_csrf),
):
    row = db.get(Backup, backup_id)
    if row is None:
        raise AppError("BACKUP_NOT_FOUND", "Backup not found", 404)
    service = BackupService(db)
    safety = service.create(f"automatic safety backup before restore {backup_id}", principal.username)
    db.commit()
    safety_id = safety.id
    try:
        service.restore(row)
    except Exception as exc:
        rollback_error = None
        try:
            safety_row = db.get(Backup, safety_id) or safety
            service.restore(safety_row)
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc)
        details = f"restore failed: {exc}" + (f"; safety rollback failed: {rollback_error}" if rollback_error else "; safety rollback succeeded")
        write_audit(db, principal, get_client_ip(request), "RESTORE_BACKUP", "FAILED", new_value={"backup_id": backup_id, "safety_backup_id": safety_id}, details=details)
        if rollback_error:
            raise AppError("RESTORE_ROLLBACK_FAILED", "Backup restore failed and safety rollback also failed", 500, details) from exc
        raise AppError("RESTORE_FAILED", "Backup restore failed and the previous state was restored", 422, details) from exc
    write_audit(db, principal, get_client_ip(request), "RESTORE_BACKUP", "SUCCESS", new_value={"backup_id": backup_id, "safety_backup_id": safety_id})
    return {"status": "restored", "backup_id": backup_id, "safety_backup_id": safety_id}


@backups_router.delete("/{backup_id}", status_code=204, summary="Delete backup", description="Requires backups.restore.")
def delete_backup(
    backup_id: int, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("backups.restore")), _: Principal = Depends(enforce_api_csrf),
):
    row = db.get(Backup, backup_id)
    if row is None:
        raise AppError("BACKUP_NOT_FOUND", "Backup not found", 404)
    BackupService(db).delete(row)
    write_audit(db, principal, get_client_ip(request), "DELETE_BACKUP", "SUCCESS", old_value={"backup_id": backup_id, "filename": row.filename})
    return Response(status_code=204)


@audit_router.get("", summary="Read audit log", description="Requires audit.read.")
def audit_log(
    q: str | None = None, action: str | None = None, result: str | None = None,
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
    page: int | None = Query(None, ge=1), page_size: int | None = Query(None, ge=1, le=500),
    db: Session = Depends(get_db), principal: Principal = Depends(require_permission("audit.read")),
):
    if page is not None or page_size is not None:
        effective_size = page_size or limit
        effective_page = page or 1
        limit, offset = effective_size, (effective_page - 1) * effective_size
    stmt = select(AuditLog)
    count_stmt = select(func.count(AuditLog.id))
    conditions = []
    if q:
        pattern = f"%{q.strip()}%"
        from sqlalchemy import or_
        conditions.append(or_(AuditLog.username.ilike(pattern), AuditLog.ip.ilike(pattern), AuditLog.zone.ilike(pattern), AuditLog.record.ilike(pattern), AuditLog.details.ilike(pattern)))
    if action:
        conditions.append(AuditLog.action == action)
    if result:
        conditions.append(AuditLog.result == result)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)
    rows = list(db.scalars(stmt.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)))
    return {"items": [{"id": x.id, "timestamp": x.timestamp, "username": x.username, "ip": x.ip, "action": x.action, "zone": x.zone, "record": x.record, "old_value": x.old_value, "new_value": x.new_value, "result": x.result, "details": x.details} for x in rows], "total": db.scalar(count_stmt) or 0, "limit": limit, "offset": offset}


@tokens_router.get("", summary="List API tokens", description="Requires tokens.manage.")
def list_tokens(db: Session = Depends(get_db), principal: Principal = Depends(require_permission("tokens.manage"))):
    rows = list(db.scalars(select(ApiToken).order_by(ApiToken.created_at.desc())))
    return {"items": [{"id": x.id, "name": x.name, "token_prefix": x.token_prefix, "user_id": x.user_id, "permissions": json.loads(x.permissions), "enabled": x.enabled, "created_at": x.created_at, "last_used": x.last_used, "expires_at": x.expires_at} for x in rows]}


@tokens_router.post("", response_model=TokenCreated, status_code=201, summary="Create API token", description="Requires tokens.manage. The plaintext token is returned exactly once.")
def create_token(
    payload: TokenCreate, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tokens.manage")), _: Principal = Depends(enforce_api_csrf),
):
    unknown = set(payload.permissions) - ALL_PERMISSIONS
    if unknown:
        raise AppError("INVALID_PERMISSIONS", "Unknown API token permissions", 422, ", ".join(sorted(unknown)))
    if payload.expires_at:
        expires = payload.expires_at if payload.expires_at.tzinfo else payload.expires_at.replace(tzinfo=timezone.utc)
        if expires <= datetime.now(timezone.utc):
            raise AppError("INVALID_EXPIRY", "Token expiry must be in the future", 422)
    raw = create_api_token()
    row = ApiToken(user_id=principal.user_id, name=payload.name, token_hash=token_digest(raw), token_prefix=raw[:18], permissions=json.dumps(sorted(set(payload.permissions))), expires_at=payload.expires_at)
    db.add(row)
    db.commit()
    db.refresh(row)
    write_audit(db, principal, get_client_ip(request), "CREATE_API_TOKEN", "SUCCESS", new_value={"token_id": row.id, "name": row.name, "permissions": payload.permissions})
    return TokenCreated(id=row.id, name=row.name, token=raw, permissions=payload.permissions, expires_at=row.expires_at)


@tokens_router.delete("/{token_id}", status_code=204, summary="Revoke API token", description="Requires tokens.manage.")
def revoke_token(
    token_id: int, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tokens.manage")), _: Principal = Depends(enforce_api_csrf),
):
    row = db.get(ApiToken, token_id)
    if row is None:
        raise AppError("TOKEN_NOT_FOUND", "API token not found", 404)
    row.enabled = False
    db.commit()
    write_audit(db, principal, get_client_ip(request), "REVOKE_API_TOKEN", "SUCCESS", old_value={"token_id": token_id, "name": row.name})
    return Response(status_code=204)


@users_router.get("", summary="List users", description="Requires users.manage.")
def list_users(db: Session = Depends(get_db), principal: Principal = Depends(require_permission("users.manage"))):
    rows = list(db.scalars(select(User).order_by(User.username)))
    return {"items": [{"id": x.id, "username": x.username, "role": x.role, "enabled": x.enabled, "theme": x.theme, "created_at": x.created_at} for x in rows]}


@users_router.post("", status_code=201, summary="Create user", description="Requires users.manage. Passwords are stored with Argon2id.")
def create_user(
    payload: UserCreate, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users.manage")), _: Principal = Depends(enforce_api_csrf),
):
    if db.scalar(select(User.id).where(User.username == payload.username)) is not None:
        raise AppError("USER_EXISTS", "Username already exists", 409)
    user = User(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    write_audit(db, principal, get_client_ip(request), "CREATE_USER", "SUCCESS", new_value={"user_id": user.id, "username": user.username, "role": user.role})
    return {"id": user.id, "username": user.username, "role": user.role, "enabled": user.enabled}


@users_router.put("/{user_id}", summary="Update user", description="Requires users.manage. The last enabled administrator cannot be disabled or demoted.")
def update_user(
    user_id: int, payload: UserUpdate, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users.manage")), _: Principal = Depends(enforce_api_csrf),
):
    user = db.get(User, user_id)
    if user is None:
        raise AppError("USER_NOT_FOUND", "User not found", 404)
    next_role = payload.role if payload.role is not None else user.role
    next_enabled = payload.enabled if payload.enabled is not None else user.enabled
    if user.id == principal.user_id and not next_enabled:
        raise AppError("SELF_DISABLE_FORBIDDEN", "You cannot disable your own active session", 409)
    if user.role == "administrator" and user.enabled and (next_role != "administrator" or not next_enabled):
        enabled_admins = db.scalar(select(func.count(User.id)).where(User.role == "administrator", User.enabled.is_(True))) or 0
        if enabled_admins <= 1:
            raise AppError("LAST_ADMIN", "The last enabled administrator cannot be disabled or demoted", 409)
    old = {"role": user.role, "enabled": user.enabled}
    user.role = next_role
    user.enabled = next_enabled
    db.commit()
    write_audit(db, principal, get_client_ip(request), "UPDATE_USER", "SUCCESS", old_value={"user_id": user.id, **old}, new_value={"user_id": user.id, "role": user.role, "enabled": user.enabled})
    return {"id": user.id, "username": user.username, "role": user.role, "enabled": user.enabled}


@users_router.delete("/{user_id}", status_code=204, summary="Delete user", description="Requires users.manage. Self-deletion and deletion of the last enabled administrator are blocked.")
def delete_user(
    user_id: int, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users.manage")), _: Principal = Depends(enforce_api_csrf),
):
    user = db.get(User, user_id)
    if user is None:
        raise AppError("USER_NOT_FOUND", "User not found", 404)
    if user.id == principal.user_id:
        raise AppError("SELF_DELETE_FORBIDDEN", "You cannot delete your own active account", 409)
    if user.role == "administrator" and user.enabled:
        enabled_admins = db.scalar(select(func.count(User.id)).where(User.role == "administrator", User.enabled.is_(True))) or 0
        if enabled_admins <= 1:
            raise AppError("LAST_ADMIN", "The last enabled administrator cannot be deleted", 409)
    old = {"user_id": user.id, "username": user.username, "role": user.role, "enabled": user.enabled}
    db.delete(user)
    db.commit()
    write_audit(db, principal, get_client_ip(request), "DELETE_USER", "SUCCESS", old_value=old)
    return Response(status_code=204)


@users_router.put("/{user_id}/password", summary="Change user password", description="Requires users.manage.")
def change_user_password(
    user_id: int, payload: PasswordChange, request: Request, db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users.manage")), _: Principal = Depends(enforce_api_csrf),
):
    user = db.get(User, user_id)
    if user is None:
        raise AppError("USER_NOT_FOUND", "User not found", 404)
    user.password_hash = hash_password(payload.password)
    db.commit()
    write_audit(db, principal, get_client_ip(request), "CHANGE_PASSWORD", "SUCCESS", new_value={"user_id": user.id, "username": user.username})
    return {"status": "updated"}
