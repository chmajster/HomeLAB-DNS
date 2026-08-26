import re

from sqlalchemy import select

from backend.app import authentication
from backend.app.authentication import EXTERNAL_PASSWORD_MARKER
from backend.app.models import AppState, User
from backend.app.security import hash_password, verify_password


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _login_local_admin(client, db, username: str = "admin", password: str = "admin"):
    db.add(User(username=username, password_hash=hash_password(password), role="administrator", enabled=True))
    db.commit()
    page = client.get("/login")
    assert page.status_code == 200
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": _csrf(page.text)},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_local_is_default_authentication_provider(db):
    db.add(User(username="admin", password_hash=hash_password("admin"), role="administrator", enabled=True))
    db.commit()
    assert authentication.get_auth_mode(db) == "local"
    assert authentication.authenticate_identity(db, "admin", "admin") == "local"
    assert authentication.authenticate_identity(db, "admin", "wrong") is None


def test_local_login_works_through_web(client, db):
    _login_local_admin(client, db)
    dashboard = client.get("/")
    assert dashboard.status_code == 200


def test_local_credentials_can_be_changed_after_login(client, db):
    _login_local_admin(client, db)
    settings = client.get("/settings")
    assert settings.status_code == 200
    response = client.post(
        "/settings/local-account",
        data={
            "csrf_token": _csrf(settings.text),
            "current_password": "admin",
            "new_username": "chris",
            "new_password": "1",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    db.expire_all()
    user = db.scalar(select(User).where(User.username == "chris"))
    assert user is not None
    assert verify_password(user.password_hash, "1")
    assert db.scalar(select(User.id).where(User.username == "admin")) is None


def test_authentication_mode_can_be_changed_in_settings(client, db):
    _login_local_admin(client, db)
    settings = client.get("/settings")
    response = client.post(
        "/settings/authentication",
        data={"csrf_token": _csrf(settings.text), "auth_mode": "pam"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert authentication.get_auth_mode(db) == "pam"

    settings = client.get("/settings")
    response = client.post(
        "/settings/authentication",
        data={
            "csrf_token": _csrf(settings.text),
            "auth_mode": "ldap",
            "ldap_url": "ldap://ldap.example.test:389",
            "ldap_base_dn": "dc=example,dc=test",
            "ldap_user_filter": "(uid={username})",
            "ldap_default_role": "read_only",
            "ldap_verify_tls": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert authentication.get_auth_mode(db) == "ldap"
    ldap = authentication.get_ldap_settings(db)
    assert ldap.enabled is True
    assert ldap.base_dn == "dc=example,dc=test"


def test_pam_mode_uses_only_pam(db, monkeypatch):
    authentication.save_auth_mode(db, "pam")
    monkeypatch.setattr(authentication, "authenticate_pam", lambda username, password: username == "linux-user" and password == "secret")
    monkeypatch.setattr(authentication, "authenticate_ldap", lambda _db, username, password: True)
    assert authentication.authenticate_identity(db, "linux-user", "secret") == "pam"
    assert authentication.authenticate_identity(db, "other", "secret") is None


def test_ldap_mode_uses_only_ldap(db, monkeypatch):
    authentication.save_auth_mode(db, "ldap")
    monkeypatch.setattr(authentication, "authenticate_pam", lambda username, password: True)
    monkeypatch.setattr(authentication, "authenticate_ldap", lambda _db, username, password: username == "ldap-user" and password == "secret")
    assert authentication.authenticate_identity(db, "ldap-user", "secret") == "ldap"
    assert authentication.authenticate_identity(db, "linux-user", "secret") is None


def test_invalid_auth_mode_is_rejected(db):
    try:
        authentication.save_auth_mode(db, "mixed")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid authentication mode was accepted")


def test_external_pam_identity_is_read_only_when_admin_exists(db):
    db.add(User(username="local-admin", password_hash=hash_password("secret"), role="administrator", enabled=True))
    db.commit()
    user = authentication.ensure_authorization_profile(db, "first-linux-user", "pam")
    assert user.role == "read_only"
    assert user.password_hash == EXTERNAL_PASSWORD_MARKER


def test_existing_local_profile_is_not_rewritten_by_external_login(db):
    original_hash = hash_password("local-secret")
    user = User(username="admin", password_hash=original_hash, role="administrator", enabled=True)
    db.add(user)
    db.commit()
    result = authentication.ensure_authorization_profile(db, "admin", "pam")
    assert result.id == user.id
    assert result.password_hash == original_hash


def test_ldap_default_role_is_used_after_external_bootstrap(db):
    db.add(User(username="external-admin", password_hash=EXTERNAL_PASSWORD_MARKER, role="administrator", enabled=True))
    db.commit()
    authentication.save_ldap_settings(
        db,
        enabled=True,
        url="ldap://ldap.example.test:389",
        start_tls=False,
        verify_tls=True,
        base_dn="dc=example,dc=test",
        bind_dn="",
        bind_password=None,
        clear_bind_password=False,
        user_filter="(&(objectClass=person)(uid={username}))",
        default_role="operator",
    )
    user = authentication.ensure_authorization_profile(db, "ldap-user", "ldap")
    assert user.role == "operator"


def test_ldap_bind_password_is_encrypted_at_rest(db):
    authentication.save_ldap_settings(
        db,
        enabled=True,
        url="ldaps://ldap.example.test:636",
        start_tls=False,
        verify_tls=True,
        base_dn="dc=example,dc=test",
        bind_dn="cn=service,dc=example,dc=test",
        bind_password="bind-secret",
        clear_bind_password=False,
        user_filter="(uid={username})",
        default_role="read_only",
    )
    stored = db.scalar(select(AppState.value).where(AppState.key == authentication.LDAP_KEYS["bind_password"]))
    assert stored is not None
    assert stored != "bind-secret"
    assert authentication.get_ldap_settings(db).bind_password == "bind-secret"
