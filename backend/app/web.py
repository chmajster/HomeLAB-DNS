from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .authentication import (
    authenticate_identity,
    ensure_authorization_profile,
    get_ldap_settings,
    save_ldap_settings,
    test_ldap_connection,
)
from .database import get_db
from .errors import AppError
from .models import ApiToken, AppState, AuditLog, Backup, Record, User, Zone
from .permissions import ROLE_PERMISSIONS
from .security import ensure_csrf, ensure_csrf_token, get_client_ip, rate_limiter
from .services.bind import BindService

PROJECT_ROOT = Path(__file__).resolve().parents[2]
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "frontend" / "templates"))
router = APIRouter(include_in_schema=False)


def _current_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = db.get(User, int(user_id))
    if user is None or not user.enabled:
        request.session.clear()
        return None
    return user


def _require_user(request: Request, db: Session) -> User:
    user = _current_user(request, db)
    if user is None:
        raise AppError("WEB_LOGIN_REQUIRED", "Login required", 401)
    return user


def _context(request: Request, db: Session, **extra):
    user = _current_user(request, db)
    data = {
        "request": request,
        "user": user,
        "csrf_token": ensure_csrf_token(request),
        "permissions": ROLE_PERMISSIONS.get(user.role, set()) if user else set(),
        "theme": user.theme if user else "system",
        "auth_type": request.session.get("auth_type") if user else None,
    }
    data.update(extra)
    return data


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if _current_user(request, db):
        return RedirectResponse("/", status_code=303)
    ldap = get_ldap_settings(db)
    return templates.TemplateResponse(request, "login.html", _context(request, db, ldap_enabled=ldap.enabled))


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    ensure_csrf(request, csrf_token)
    ip = get_client_ip(request)
    rate_limiter.check(f"login:{ip}", 5, 300)
    normalized_username = username.strip()
    auth_type = authenticate_identity(db, normalized_username, password)
    if auth_type is None:
        return templates.TemplateResponse(
            request,
            "login.html",
            _context(
                request,
                db,
                error="Nieprawidłowa nazwa użytkownika lub hasło.",
                ldap_enabled=get_ldap_settings(db).enabled,
            ),
            status_code=401,
        )

    user = ensure_authorization_profile(db, normalized_username, auth_type)
    if not user.enabled:
        return templates.TemplateResponse(
            request,
            "login.html",
            _context(
                request,
                db,
                error="Konto jest wyłączone w ChrisLab DNS.",
                ldap_enabled=get_ldap_settings(db).enabled,
            ),
            status_code=403,
        )

    request.session.clear()
    request.session["user_id"] = user.id
    request.session["auth_type"] = auth_type
    ensure_csrf_token(request)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    ensure_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    bind_status = {"active": False, "version": "unavailable", "pid": None, "uptime_seconds": None, "zones": None, "recursive_clients": None}
    config_valid = False
    try:
        bind_status = BindService().status()
        BindService().validate_config()
        config_valid = True
    except AppError:
        config_valid = False
    stats = {
        "zones": db.scalar(select(func.count(Zone.id))) or 0,
        "records": db.scalar(select(func.count(Record.id))) or 0,
        "last_change": db.scalar(select(func.max(AuditLog.timestamp))),
        "last_backup": db.scalar(select(func.max(Backup.created_at))),
        "last_reload": (db.get(AppState, "last_reload").value if db.get(AppState, "last_reload") else None),
        "config_errors": 0 if config_valid else 1,
    }
    return templates.TemplateResponse(request, "dashboard.html", _context(request, db, bind=bind_status, config_valid=config_valid, stats=stats))


@router.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = "", db: Session = Depends(get_db)):
    _require_user(request, db)
    query = q.strip()
    zones = []
    rows = []
    if query:
        pattern = f"%{query}%"
        zones = list(db.scalars(select(Zone).where(Zone.name.ilike(pattern)).order_by(Zone.name).limit(100)))
        rows = list(db.execute(select(Record, Zone).join(Zone, Record.zone_id == Zone.id).where(or_(Zone.name.ilike(pattern), Record.name.ilike(pattern), Record.value.ilike(pattern), Record.type.ilike(pattern))).order_by(Zone.name, Record.name).limit(250)))
    return templates.TemplateResponse(request, "search.html", _context(request, db, q=query, zones=zones, rows=rows))


@router.get("/zones", response_class=HTMLResponse)
def zones_page(request: Request, q: str | None = None, db: Session = Depends(get_db)):
    _require_user(request, db)
    stmt = select(Zone).order_by(Zone.name)
    if q:
        stmt = stmt.where(Zone.name.ilike(f"%{q.strip()}%"))
    zones = list(db.scalars(stmt.limit(500)))
    return templates.TemplateResponse(request, "zones.html", _context(request, db, zones=zones, q=q or ""))


@router.get("/zones/{zone_name}", response_class=HTMLResponse)
def zone_detail(request: Request, zone_name: str, db: Session = Depends(get_db)):
    _require_user(request, db)
    zone = db.scalar(select(Zone).where(Zone.name == zone_name.rstrip(".").lower()))
    if zone is None:
        raise AppError("ZONE_NOT_FOUND", "Zone not found", 404)
    records = list(db.scalars(select(Record).where(Record.zone_id == zone.id).order_by(Record.name, Record.type, Record.id)))
    return templates.TemplateResponse(request, "zone_detail.html", _context(request, db, zone=zone, records=records))


@router.get("/records", response_class=HTMLResponse)
def records_page(request: Request, q: str | None = None, db: Session = Depends(get_db)):
    _require_user(request, db)
    stmt = select(Record, Zone).join(Zone, Record.zone_id == Zone.id).order_by(Zone.name, Record.name).limit(500)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(or_(Zone.name.ilike(pattern), Record.name.ilike(pattern), Record.value.ilike(pattern), Record.type.ilike(pattern)))
    rows = list(db.execute(stmt))
    return templates.TemplateResponse(request, "records.html", _context(request, db, rows=rows, q=q or ""))


@router.get("/dns-lookup", response_class=HTMLResponse)
def lookup_page(request: Request, name: str = "", type: str = "A", server: str = "", db: Session = Depends(get_db)):
    _require_user(request, db)
    allowed = {"A", "AAAA", "MX", "TXT", "NS", "PTR", "CNAME", "SOA", "SRV", "CAA", "ANY"}
    lookup_type = type.upper() if type.upper() in allowed else "A"
    return templates.TemplateResponse(request, "lookup.html", _context(request, db, lookup_name=name, lookup_type=lookup_type, lookup_server=server))


@router.get("/backups", response_class=HTMLResponse)
def backups_page(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    rows = list(db.scalars(select(Backup).order_by(Backup.created_at.desc()).limit(500)))
    return templates.TemplateResponse(request, "backups.html", _context(request, db, backups=rows))


@router.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    return templates.TemplateResponse(request, "logs.html", _context(request, db))


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, q: str = "", action: str = "", result: str = "", db: Session = Depends(get_db)):
    _require_user(request, db)
    stmt = select(AuditLog)
    if q.strip():
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(or_(AuditLog.username.ilike(pattern), AuditLog.ip.ilike(pattern), AuditLog.zone.ilike(pattern), AuditLog.record.ilike(pattern), AuditLog.details.ilike(pattern)))
    if action.strip():
        stmt = stmt.where(AuditLog.action == action.strip())
    if result in {"SUCCESS", "FAILED"}:
        stmt = stmt.where(AuditLog.result == result)
    rows = list(db.scalars(stmt.order_by(AuditLog.timestamp.desc()).limit(500)))
    actions = list(db.scalars(select(AuditLog.action).distinct().order_by(AuditLog.action)))
    return templates.TemplateResponse(request, "audit.html", _context(request, db, logs=rows, q=q, action=action, result=result, actions=actions))


@router.get("/api-tokens", response_class=HTMLResponse)
def tokens_page(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    if "tokens.manage" not in ROLE_PERMISSIONS.get(user.role, set()):
        raise AppError("FORBIDDEN", "Permission required: tokens.manage", 403)
    rows = list(db.scalars(select(ApiToken).order_by(ApiToken.created_at.desc())))
    return templates.TemplateResponse(request, "tokens.html", _context(request, db, tokens=rows, all_permissions=sorted({p for perms in ROLE_PERMISSIONS.values() for p in perms})))


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    if "users.manage" not in ROLE_PERMISSIONS.get(user.role, set()):
        raise AppError("FORBIDDEN", "Permission required: users.manage", 403)
    users = list(db.scalars(select(User).order_by(User.username)))
    return templates.TemplateResponse(request, "users.html", _context(request, db, users=users))


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    ldap = get_ldap_settings(db)
    return templates.TemplateResponse(
        request,
        "settings.html",
        _context(
            request,
            db,
            ldap=ldap,
            ldap_bind_password_set=bool(ldap.bind_password),
            can_manage_auth="settings.manage" in ROLE_PERMISSIONS.get(user.role, set()),
            saved=request.query_params.get("saved") == "1",
            ldap_test=request.query_params.get("ldap_test", ""),
        ),
    )


@router.post("/settings/theme")
def update_theme(
    request: Request,
    theme: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    ensure_csrf(request, csrf_token)
    if theme not in {"light", "dark", "system"}:
        raise AppError("INVALID_THEME", "Invalid theme", 422)
    user.theme = theme
    db.commit()
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/authentication")
def update_authentication_settings(
    request: Request,
    csrf_token: str = Form(...),
    ldap_enabled: str | None = Form(None),
    ldap_url: str = Form(...),
    ldap_start_tls: str | None = Form(None),
    ldap_verify_tls: str | None = Form(None),
    ldap_base_dn: str = Form(...),
    ldap_bind_dn: str = Form(""),
    ldap_bind_password: str = Form(""),
    ldap_clear_bind_password: str | None = Form(None),
    ldap_user_filter: str = Form(...),
    ldap_default_role: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in ROLE_PERMISSIONS.get(user.role, set()):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    try:
        save_ldap_settings(
            db,
            enabled=ldap_enabled == "on",
            url=ldap_url,
            start_tls=ldap_start_tls == "on",
            verify_tls=ldap_verify_tls == "on",
            base_dn=ldap_base_dn,
            bind_dn=ldap_bind_dn,
            bind_password=ldap_bind_password or None,
            clear_bind_password=ldap_clear_bind_password == "on",
            user_filter=ldap_user_filter,
            default_role=ldap_default_role,
        )
    except ValueError as exc:
        raise AppError("INVALID_LDAP_SETTINGS", str(exc), 422) from exc
    return RedirectResponse("/settings?saved=1", status_code=303)


@router.post("/settings/authentication/test")
def test_authentication_settings(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in ROLE_PERMISSIONS.get(user.role, set()):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    ok, _message = test_ldap_connection(db)
    return RedirectResponse(f"/settings?ldap_test={'ok' if ok else 'failed'}", status_code=303)


@router.get("/synchronize", response_class=HTMLResponse)
def synchronize_page(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    return templates.TemplateResponse(request, "synchronize.html", _context(request, db))
