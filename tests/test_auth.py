import json

from sqlalchemy import select

from backend.app import cli
from backend.app.authentication import get_auth_mode
from backend.app.models import ApiToken, User
from backend.app.permissions import ALL_PERMISSIONS
from backend.app.security import create_api_token, hash_password, token_digest, verify_password


def test_argon2id_password_hash():
    hashed = hash_password("Long-Password-123!")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "Long-Password-123!")
    assert not verify_password(hashed, "wrong")


def test_migrate_bootstraps_default_local_admin(db):
    cli.migrate()
    db.expire_all()
    user = db.scalar(select(User).where(User.username == "admin"))
    assert user is not None
    assert user.role == "administrator"
    assert user.enabled is True
    assert verify_password(user.password_hash, "admin")
    assert get_auth_mode(db) == "local"


def test_migrate_does_not_reset_existing_credentials(db):
    user = User(username="custom", password_hash=hash_password("secret"), role="administrator", enabled=True)
    db.add(user)
    db.commit()
    original_hash = user.password_hash
    cli.migrate()
    db.expire_all()
    stored = db.scalar(select(User).where(User.username == "custom"))
    assert stored is not None
    assert stored.password_hash == original_hash
    assert db.scalar(select(User.id).where(User.username == "admin")) is None


def test_unauthorized_api_is_401(client):
    response = client.get("/api/v1/zones")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_read_only_cannot_create_zone(client, readonly_token):
    response = client.post("/api/v1/zones", headers={"Authorization": f"Bearer {readonly_token}"}, json={"name":"example.com"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_api_token_plaintext_not_stored(db, admin_token):
    row = db.scalar(select(ApiToken).where(ApiToken.token_hash == token_digest(admin_token)))
    assert row is not None
    assert admin_token not in row.token_hash
    assert len(row.token_hash) == 64
