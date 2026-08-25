from sqlalchemy import select

from backend.app import authentication
from backend.app.authentication import EXTERNAL_PASSWORD_MARKER
from backend.app.models import AppState, User
from backend.app.security import hash_password


def test_local_is_default_authentication_provider(db):
    db.add(User(username="admin", password_hash=hash_password("admin"), role="administrator", enabled=True))
    db.commit()
    assert authentication.get_auth_mode(db) == "local"
    assert authentication.authenticate_identity(db, "admin", "admin") == "local"
    assert authentication.authenticate_identity(db, "admin", "wrong") is None


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


def test_first_external_identity_bootstraps_administrator(db):
    user = authentication.ensure_authorization_profile(db, "first-linux-user", "pam")
    assert user.role == "administrator"
    assert user.password_hash == EXTERNAL_PASSWORD_MARKER


def test_existing_local_profile_is_not_rewritten_by_external_login(db):
    original_hash = hash_password("local-secret")
    user = User(username="admin", password_hash=original_hash, role="administrator", enabled=True)
    db.add(user)
    db.commit()
    result = authentication.ensure_authorization_profile(db, "admin", "pam")
    assert result.id == user.id
    assert result.password_hash == original_hash


def test_ldap_default_role_is_used_after_bootstrap(db):
    db.add(User(username="local-admin", password_hash=hash_password("secret"), role="administrator", enabled=True))
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
