from __future__ import annotations

import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AppState, User
from .security import decrypt_secret, encrypt_secret, verify_password


EXTERNAL_PASSWORD_MARKER = "!external-auth!"
AUTH_MODE_KEY = "auth.mode"
AUTH_MODES = {"local", "pam", "ldap"}


@dataclass(frozen=True)
class LdapSettings:
    enabled: bool = False
    url: str = "ldap://127.0.0.1:389"
    start_tls: bool = False
    verify_tls: bool = True
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    user_filter: str = "(&(objectClass=person)(uid={username}))"
    default_role: str = "read_only"
    administrator_group_dn: str = ""
    operator_group_dn: str = ""
    read_only_group_dn: str = ""


LDAP_KEYS = {
    "enabled": "auth.ldap.enabled",
    "url": "auth.ldap.url",
    "start_tls": "auth.ldap.start_tls",
    "verify_tls": "auth.ldap.verify_tls",
    "base_dn": "auth.ldap.base_dn",
    "bind_dn": "auth.ldap.bind_dn",
    "bind_password": "auth.ldap.bind_password",
    "user_filter": "auth.ldap.user_filter",
    "default_role": "auth.ldap.default_role",
    "administrator_group_dn": "auth.ldap.group.administrator",
    "operator_group_dn": "auth.ldap.group.operator",
    "read_only_group_dn": "auth.ldap.group.read_only",
}


def _state_get(db: Session, key: str, default: str = "") -> str:
    row = db.get(AppState, key)
    return row.value if row is not None else default


def _state_set(db: Session, key: str, value: str) -> None:
    row = db.get(AppState, key)
    if row is None:
        db.add(AppState(key=key, value=value))
    else:
        row.value = value


def get_auth_mode(db: Session) -> str:
    mode = _state_get(db, AUTH_MODE_KEY, "local").strip().lower()
    return mode if mode in AUTH_MODES else "local"


def save_auth_mode(db: Session, mode: str) -> None:
    normalized = mode.strip().lower()
    if normalized not in AUTH_MODES:
        raise ValueError("Authentication mode must be local, pam or ldap")
    _state_set(db, AUTH_MODE_KEY, normalized)
    db.commit()


def _bool_value(value: str, default: bool = False) -> bool:
    if not value:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_ldap_settings(db: Session) -> LdapSettings:
    return LdapSettings(
        enabled=_bool_value(_state_get(db, LDAP_KEYS["enabled"], "false")),
        url=_state_get(db, LDAP_KEYS["url"], "ldap://127.0.0.1:389"),
        start_tls=_bool_value(_state_get(db, LDAP_KEYS["start_tls"], "false")),
        verify_tls=_bool_value(_state_get(db, LDAP_KEYS["verify_tls"], "true"), True),
        base_dn=_state_get(db, LDAP_KEYS["base_dn"]),
        bind_dn=_state_get(db, LDAP_KEYS["bind_dn"]),
        bind_password=decrypt_secret(_state_get(db, LDAP_KEYS["bind_password"])),
        user_filter=_state_get(db, LDAP_KEYS["user_filter"], "(&(objectClass=person)(uid={username}))"),
        default_role=_state_get(db, LDAP_KEYS["default_role"], "read_only"),
        administrator_group_dn=_state_get(db, LDAP_KEYS["administrator_group_dn"]),
        operator_group_dn=_state_get(db, LDAP_KEYS["operator_group_dn"]),
        read_only_group_dn=_state_get(db, LDAP_KEYS["read_only_group_dn"]),
    )


def save_ldap_settings(
    db: Session,
    *,
    enabled: bool,
    url: str,
    start_tls: bool,
    verify_tls: bool,
    base_dn: str,
    bind_dn: str,
    bind_password: str | None,
    clear_bind_password: bool,
    user_filter: str,
    default_role: str,
    administrator_group_dn: str = "",
    operator_group_dn: str = "",
    read_only_group_dn: str = "",
) -> None:
    if default_role not in {"administrator", "operator", "read_only"}:
        raise ValueError("Invalid LDAP default role")
    if "{username}" not in user_filter:
        raise ValueError("LDAP user filter must contain {username}")
    parsed = urlparse(url)
    if parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname:
        raise ValueError("LDAP URL must use ldap:// or ldaps://")
    if not base_dn.strip():
        raise ValueError("LDAP base DN is required")
    if parsed.scheme == "ldaps" and start_tls:
        raise ValueError("StartTLS cannot be enabled with ldaps://")

    _state_set(db, LDAP_KEYS["enabled"], "true" if enabled else "false")
    _state_set(db, LDAP_KEYS["url"], url.strip())
    _state_set(db, LDAP_KEYS["start_tls"], "true" if start_tls else "false")
    _state_set(db, LDAP_KEYS["verify_tls"], "true" if verify_tls else "false")
    _state_set(db, LDAP_KEYS["base_dn"], base_dn.strip())
    _state_set(db, LDAP_KEYS["bind_dn"], bind_dn.strip())
    _state_set(db, LDAP_KEYS["user_filter"], user_filter.strip())
    _state_set(db, LDAP_KEYS["default_role"], default_role)
    _state_set(db, LDAP_KEYS["administrator_group_dn"], administrator_group_dn.strip())
    _state_set(db, LDAP_KEYS["operator_group_dn"], operator_group_dn.strip())
    _state_set(db, LDAP_KEYS["read_only_group_dn"], read_only_group_dn.strip())
    if clear_bind_password:
        _state_set(db, LDAP_KEYS["bind_password"], "")
    elif bind_password:
        _state_set(db, LDAP_KEYS["bind_password"], encrypt_secret(bind_password))
    db.commit()


def authenticate_local(db: Session, username: str, password: str) -> bool:
    if not username or not password:
        return False
    user = db.scalar(select(User).where(User.username == username, User.enabled.is_(True)))
    if user is None or user.password_hash == EXTERNAL_PASSWORD_MARKER:
        return False
    return verify_password(user.password_hash, password)


def authenticate_pam(username: str, password: str) -> bool:
    if not username or not password:
        return False
    try:
        import pam

        client = pam.pam()
        return bool(client.authenticate(username, password, service="chrislab-dns"))
    except Exception:
        return False


def _ldap_server(settings: LdapSettings):
    from ldap3 import Server, Tls

    parsed = urlparse(settings.url)
    use_ssl = parsed.scheme == "ldaps"
    port = parsed.port or (636 if use_ssl else 389)
    tls = Tls(validate=ssl.CERT_REQUIRED if settings.verify_tls else ssl.CERT_NONE)
    return Server(parsed.hostname, port=port, use_ssl=use_ssl, tls=tls, connect_timeout=8)


def _open_ldap_connection(server, settings: LdapSettings, user: str = "", password: str = ""):
    from ldap3 import Connection

    conn = Connection(server, user=user or None, password=password or None, receive_timeout=8, raise_exceptions=False)
    if not conn.open():
        return None
    if settings.start_tls and not conn.start_tls():
        conn.unbind()
        return None
    if not conn.bind():
        conn.unbind()
        return None
    return conn


def _search_ldap_user(settings: LdapSettings, username: str, attributes: list[str]):
    from ldap3.utils.conv import escape_filter_chars

    server = _ldap_server(settings)
    service_conn = _open_ldap_connection(server, settings, settings.bind_dn, settings.bind_password)
    if service_conn is None:
        return None, None
    search_filter = settings.user_filter.replace("{username}", escape_filter_chars(username))
    ok = service_conn.search(settings.base_dn, search_filter, attributes=attributes)
    if not ok or len(service_conn.entries) != 1:
        service_conn.unbind()
        return None, None
    entry = service_conn.entries[0]
    return service_conn, entry


def authenticate_ldap(db: Session, username: str, password: str) -> bool:
    settings = get_ldap_settings(db)
    if not settings.enabled or not username or not password:
        return False
    try:
        service_conn, entry = _search_ldap_user(settings, username, [])
        if service_conn is None or entry is None:
            return False
        user_dn = entry.entry_dn
        service_conn.unbind()
        user_conn = _open_ldap_connection(_ldap_server(settings), settings, user_dn, password)
        if user_conn is None:
            return False
        user_conn.unbind()
        return True
    except Exception:
        return False


def resolve_ldap_role(db: Session, username: str) -> str:
    settings = get_ldap_settings(db)
    try:
        conn, entry = _search_ldap_user(settings, username, ["memberOf"])
        if conn is None or entry is None:
            return settings.default_role
        try:
            raw_groups = getattr(entry, "memberOf", None)
            values = list(raw_groups.values) if raw_groups is not None else []
        finally:
            conn.unbind()
        groups = {str(value).strip().casefold() for value in values}
        mappings = (
            (settings.administrator_group_dn, "administrator"),
            (settings.operator_group_dn, "operator"),
            (settings.read_only_group_dn, "read_only"),
        )
        for dn, role in mappings:
            if dn and dn.strip().casefold() in groups:
                return role
    except Exception:
        pass
    return settings.default_role


def test_ldap_connection(db: Session) -> tuple[bool, str]:
    settings = get_ldap_settings(db)
    try:
        server = _ldap_server(settings)
        conn = _open_ldap_connection(server, settings, settings.bind_dn, settings.bind_password)
        if conn is None:
            return False, "LDAP bind failed"
        ok = conn.search(settings.base_dn, "(objectClass=*)", search_scope="BASE", attributes=[])
        conn.unbind()
        return (True, "LDAP connection successful") if ok else (False, "LDAP base DN lookup failed")
    except Exception as exc:
        return False, f"LDAP connection failed: {exc}"


def authenticate_identity(db: Session, username: str, password: str) -> str | None:
    username = username.strip()
    mode = get_auth_mode(db)
    if mode == "local" and authenticate_local(db, username, password):
        return "local"
    if mode == "pam" and authenticate_pam(username, password):
        return "pam"
    if mode == "ldap" and authenticate_ldap(db, username, password):
        return "ldap"
    return None


def _active_admin_count(db: Session) -> int:
    return int(db.scalar(select(func.count(User.id)).where(User.role == "administrator", User.enabled.is_(True))) or 0)


def ensure_authorization_profile(db: Session, username: str, auth_type: str) -> User:
    user = db.scalar(select(User).where(User.username == username))
    if user is not None:
        if auth_type == "ldap":
            mapped_role = resolve_ldap_role(db, username)
            if mapped_role != user.role:
                # Never silently remove the final enabled administrator.
                if not (user.role == "administrator" and mapped_role != "administrator" and _active_admin_count(db) <= 1):
                    user.role = mapped_role
                    db.commit()
                    db.refresh(user)
        return user

    if _active_admin_count(db) == 0:
        role = "administrator"
    elif auth_type == "ldap":
        role = resolve_ldap_role(db, username)
    else:
        role = "read_only"

    user = User(username=username, password_hash=EXTERNAL_PASSWORD_MARKER, role=role, enabled=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
