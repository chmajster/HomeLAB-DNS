from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from .authentication import authenticate_identity, get_ldap_settings, save_ldap_settings
from .database import get_db
from .errors import AppError
from .models import DnsServer, TsigKey, User, Zone, ZoneRevision
from .permissions import ROLE_PERMISSIONS
from .schemas import DnsServerCreate, TsigKeyCreate, ZoneCreate, ZoneUpdate
from .security import (
    decrypt_secret,
    encrypt_secret,
    ensure_csrf,
    ensure_csrf_token,
    generate_recovery_codes,
    generate_totp_secret,
    get_client_ip,
    rate_limiter,
    recovery_code_digest,
    totp_uri,
    verify_totp,
)
from .services.platform import DnsPlatformService
from .services.zones import ZoneService

PROJECT_ROOT = Path(__file__).resolve().parents[2]
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "frontend" / "templates"))
router = APIRouter(include_in_schema=False)


def _user(request: Request, db: Session) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, int(user_id)) if user_id else None
    if user is None or not user.enabled:
        request.session.clear()
        raise AppError("WEB_LOGIN_REQUIRED", "Login required", 401)
    return user


def _permissions(user: User) -> set[str]:
    return set(ROLE_PERMISSIONS.get(user.role, set()))


def _context(request: Request, db: Session, **extra):
    user_id = request.session.get("user_id")
    user = db.get(User, int(user_id)) if user_id else None
    data = {
        "request": request,
        "user": user,
        "csrf_token": ensure_csrf_token(request),
        "permissions": _permissions(user) if user else set(),
        "theme": user.theme if user else "system",
        "auth_type": request.session.get("auth_type") if user else None,
    }
    data.update(extra)
    return data


def _consume_second_factor(user: User, code: str) -> bool:
    secret = decrypt_secret(user.totp_secret_encrypted or "")
    if secret and verify_totp(secret, code):
        return True
    digest = recovery_code_digest(code)
    try:
        recovery = list(json.loads(user.totp_recovery_codes or "[]"))
    except (TypeError, json.JSONDecodeError):
        recovery = []
    if digest in recovery:
        recovery.remove(digest)
        user.totp_recovery_codes = json.dumps(recovery)
        return True
    return False


def _csv_ips(value: str) -> list[str]:
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


@router.get("/login/totp", response_class=HTMLResponse)
def totp_login_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.get(User, int(user_id)) if user_id else None
    if user is None or not user.enabled or not user.totp_enabled:
        return RedirectResponse("/login", status_code=303)
    if request.session.get("totp_verified"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "totp_login.html",
        {"request": request, "csrf_token": ensure_csrf_token(request), "error": None},
    )


@router.post("/login/totp")
def totp_login(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    ensure_csrf(request, csrf_token)
    rate_limiter.check(f"totp:{get_client_ip(request)}", 10, 300)
    user_id = request.session.get("user_id")
    user = db.get(User, int(user_id)) if user_id else None
    if user is None or not user.enabled or not user.totp_enabled:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)
    if not _consume_second_factor(user, code):
        return templates.TemplateResponse(
            request,
            "totp_login.html",
            {"request": request, "csrf_token": ensure_csrf_token(request), "error": "Nieprawidłowy kod 2FA lub kod odzyskiwania."},
            status_code=401,
        )
    db.commit()
    request.session["totp_verified"] = True
    return RedirectResponse("/", status_code=303)


@router.get("/security", response_class=HTMLResponse)
def security_page(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    ldap = get_ldap_settings(db)
    setup_secret = request.session.get("totp_setup_secret")
    recovery_codes = request.session.pop("totp_recovery_plain", None)
    return templates.TemplateResponse(
        request,
        "security.html",
        _context(
            request,
            db,
            ldap=ldap,
            can_manage_auth="settings.manage" in _permissions(user),
            totp_enabled=user.totp_enabled,
            totp_setup_secret=setup_secret,
            totp_setup_uri=totp_uri(setup_secret, user.username) if setup_secret else None,
            recovery_codes=recovery_codes,
            saved=request.query_params.get("saved") == "1",
        ),
    )


@router.post("/security/2fa/start")
def start_2fa(
    request: Request,
    current_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if user.totp_enabled:
        raise AppError("TOTP_ALREADY_ENABLED", "2FA is already enabled", 409)
    if authenticate_identity(db, user.username, current_password) is None:
        raise AppError("INVALID_CURRENT_PASSWORD", "Current authentication password is incorrect", 403)
    request.session["totp_setup_secret"] = generate_totp_secret()
    return RedirectResponse("/security#two-factor", status_code=303)


@router.post("/security/2fa/confirm")
def confirm_2fa(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    secret = str(request.session.get("totp_setup_secret") or "")
    if not secret:
        raise AppError("TOTP_SETUP_MISSING", "Start 2FA setup first", 409)
    if not verify_totp(secret, code):
        raise AppError("TOTP_INVALID", "Invalid authenticator code", 422)
    recovery = generate_recovery_codes()
    user.totp_secret_encrypted = encrypt_secret(secret)
    user.totp_enabled = True
    user.totp_recovery_codes = json.dumps([recovery_code_digest(item) for item in recovery])
    db.commit()
    request.session.pop("totp_setup_secret", None)
    request.session["totp_recovery_plain"] = recovery
    request.session["totp_verified"] = True
    return RedirectResponse("/security?saved=1#two-factor", status_code=303)


@router.post("/security/2fa/disable")
def disable_2fa(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if not user.totp_enabled or not _consume_second_factor(user, code):
        raise AppError("TOTP_INVALID", "Invalid authenticator or recovery code", 403)
    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_recovery_codes = "[]"
    db.commit()
    request.session.pop("totp_verified", None)
    return RedirectResponse("/security?saved=1#two-factor", status_code=303)


@router.post("/security/ldap-groups")
def save_ldap_groups(
    request: Request,
    csrf_token: str = Form(...),
    administrator_group_dn: str = Form(""),
    operator_group_dn: str = Form(""),
    read_only_group_dn: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    current = get_ldap_settings(db)
    save_ldap_settings(
        db,
        enabled=current.enabled,
        url=current.url,
        start_tls=current.start_tls,
        verify_tls=current.verify_tls,
        base_dn=current.base_dn,
        bind_dn=current.bind_dn,
        bind_password=None,
        clear_bind_password=False,
        user_filter=current.user_filter,
        default_role=current.default_role,
        administrator_group_dn=administrator_group_dn,
        operator_group_dn=operator_group_dn,
        read_only_group_dn=read_only_group_dn,
    )
    return RedirectResponse("/security?saved=1#ldap-groups", status_code=303)


@router.get("/dns-platform", response_class=HTMLResponse)
def dns_platform_page(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if "settings.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    return templates.TemplateResponse(
        request,
        "dns_platform.html",
        _context(
            request,
            db,
            servers=list(db.scalars(select(DnsServer).order_by(DnsServer.name))),
            tsig_keys=list(db.scalars(select(TsigKey).order_by(TsigKey.name))),
            zones=list(db.scalars(select(Zone).order_by(Zone.name))),
            tsig_secret=request.session.pop("tsig_secret_once", None),
            tsig_name=request.session.pop("tsig_name_once", None),
        ),
    )


@router.post("/dns-platform/servers")
def create_server(
    request: Request,
    name: str = Form(...),
    address: str = Form(...),
    role: str = Form("secondary"),
    tsig_key_name: str = Form(""),
    notes: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    DnsPlatformService(db).create_server(
        DnsServerCreate(name=name, address=address, role=role, tsig_key_name=tsig_key_name or None, notes=notes or None)
    )
    return RedirectResponse("/dns-platform", status_code=303)


@router.post("/dns-platform/servers/{server_id}/check")
def check_server(server_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    row = db.get(DnsServer, server_id)
    if row is None:
        raise AppError("DNS_SERVER_NOT_FOUND", "DNS server not found", 404)
    DnsPlatformService(db).check_server(row)
    return RedirectResponse("/dns-platform", status_code=303)


@router.post("/dns-platform/servers/{server_id}/delete")
def delete_server(server_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    row = db.get(DnsServer, server_id)
    if row is None:
        raise AppError("DNS_SERVER_NOT_FOUND", "DNS server not found", 404)
    DnsPlatformService(db).delete_server(row)
    return RedirectResponse("/dns-platform", status_code=303)


@router.post("/dns-platform/tsig")
def create_tsig(
    request: Request,
    name: str = Form(...),
    algorithm: str = Form("hmac-sha256"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    row, secret = DnsPlatformService(db).create_tsig_key(TsigKeyCreate(name=name, algorithm=algorithm))
    request.session["tsig_secret_once"] = secret
    request.session["tsig_name_once"] = row.name
    return RedirectResponse("/dns-platform", status_code=303)


@router.post("/dns-platform/tsig/{key_id}/rotate")
def rotate_tsig(key_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    row = db.get(TsigKey, key_id)
    if row is None:
        raise AppError("TSIG_KEY_NOT_FOUND", "TSIG key not found", 404)
    service = DnsPlatformService(db)
    old = row.secret_encrypted
    secret = service.rotate_tsig_key(row, commit=False)
    try:
        ZoneService(db).apply_managed_config_only(f"before ROTATE_TSIG {row.name}", user.username)
        db.commit()
    except Exception:
        db.rollback()
        row = db.get(TsigKey, key_id)
        if row is not None:
            row.secret_encrypted = old
            db.commit()
        raise
    request.session["tsig_secret_once"] = secret
    request.session["tsig_name_once"] = row.name
    return RedirectResponse("/dns-platform", status_code=303)


@router.post("/dns-platform/tsig/{key_id}/delete")
def delete_tsig(key_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "settings.manage" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: settings.manage", 403)
    row = db.get(TsigKey, key_id)
    if row is None:
        raise AppError("TSIG_KEY_NOT_FOUND", "TSIG key not found", 404)
    DnsPlatformService(db).delete_tsig_key(row, commit=False)
    ZoneService(db).apply_managed_config_only(f"before DELETE_TSIG {row.name}", user.username)
    db.commit()
    return RedirectResponse("/dns-platform", status_code=303)


@router.post("/dns-platform/zones/secondary")
def create_secondary_zone(
    request: Request,
    name: str = Form(...),
    primary_servers: str = Form(...),
    tsig_key_name: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "zones.write" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: zones.write", 403)
    payload = ZoneCreate(
        name=name,
        zone_type="secondary",
        primary_servers=_csv_ips(primary_servers),
        tsig_key_name=tsig_key_name or None,
    )
    ZoneService(db).create(payload, user.username)
    return RedirectResponse("/dns-platform", status_code=303)


@router.post("/dns-platform/zones/{zone_name}/transfer-policy")
def update_transfer_policy(
    zone_name: str,
    request: Request,
    version: int = Form(...),
    primary_servers: str = Form(""),
    allow_transfer: str = Form(""),
    also_notify: str = Form(""),
    tsig_key_name: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "zones.write" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: zones.write", 403)
    service = ZoneService(db)
    zone = service.get(zone_name)
    payload = ZoneUpdate(
        version=version,
        primary_servers=_csv_ips(primary_servers) if zone.zone_type == "secondary" else None,
        allow_transfer=_csv_ips(allow_transfer) if zone.zone_type == "primary" else None,
        also_notify=_csv_ips(also_notify) if zone.zone_type == "primary" else None,
        tsig_key_name=tsig_key_name or None,
    )
    service.update(zone, payload, user.username)
    return RedirectResponse("/dns-platform", status_code=303)


@router.post("/dns-platform/zones/{zone_name}/retransfer")
def retransfer_secondary(
    zone_name: str,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "zones.write" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: zones.write", 403)
    zone = ZoneService(db).get(zone_name)
    if zone.zone_type != "secondary":
        raise AppError("ZONE_NOT_SECONDARY", "Zone is not a secondary zone", 422)
    ZoneService(db).bind.retransfer(zone.name)
    return RedirectResponse("/dns-platform", status_code=303)


@router.get("/zone-history/{zone_name}", response_class=HTMLResponse)
def zone_history_page(request: Request, zone_name: str, db: Session = Depends(get_db)):
    user = _user(request, db)
    if "zones.read" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: zones.read", 403)
    service = ZoneService(db)
    zone = service.get(zone_name)
    return templates.TemplateResponse(
        request,
        "zone_history.html",
        _context(request, db, zone=zone, revisions=service.list_revisions(zone.name, 500)),
    )


@router.post("/zone-history/{zone_name}/{revision_id}/restore")
def restore_revision_web(
    zone_name: str,
    revision_id: int,
    request: Request,
    version: int = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    ensure_csrf(request, csrf_token)
    if "zones.write" not in _permissions(user):
        raise AppError("FORBIDDEN", "Permission required: zones.write", 403)
    service = ZoneService(db)
    zone = service.get(zone_name)
    revision = db.get(ZoneRevision, revision_id)
    if revision is None or revision.zone_name != zone.name:
        raise AppError("REVISION_NOT_FOUND", "Zone revision not found", 404)
    service.restore_revision(zone, revision, version, user.username)
    return RedirectResponse(f"/zone-history/{zone.name}", status_code=303)
