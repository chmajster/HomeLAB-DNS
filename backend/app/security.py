from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .errors import AppError
from .models import ApiToken, User
from .permissions import ALL_PERMISSIONS, ROLE_PERMISSIONS

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_api_token() -> str:
    return "cldns_" + secrets.token_urlsafe(36)


def _fernet() -> Fernet:
    digest = hashlib.sha256(get_settings().secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError):
        return ""


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_totp_secret(secret: str) -> bytes:
    normalized = "".join(secret.upper().split())
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def totp_code(secret: str, *, timestamp: int | float | None = None, step: int = 30, digits: int = 6) -> str:
    moment = int(time.time() if timestamp is None else timestamp)
    counter = moment // step
    digest = hmac.new(_decode_totp_secret(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return f"{value:0{digits}d}"


def verify_totp(secret: str, code: str, *, timestamp: int | float | None = None, skew: int = 1) -> bool:
    candidate = "".join(code.split())
    if len(candidate) != 6 or not candidate.isdigit():
        return False
    moment = int(time.time() if timestamp is None else timestamp)
    return any(hmac.compare_digest(totp_code(secret, timestamp=moment + offset * 30), candidate) for offset in range(-skew, skew + 1))


def generate_recovery_codes(count: int = 8) -> list[str]:
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(count)]


def recovery_code_digest(code: str) -> str:
    return token_digest(code.strip().lower())


def totp_uri(secret: str, username: str, issuer: str = "ChrisLab DNS") -> str:
    label = quote(f"{issuer}:{username}", safe="")
    return f"otpauth://totp/{label}?secret={quote(secret)}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def permissions_for_user(user: User) -> set[str]:
    return set(ROLE_PERMISSIONS.get(user.role, set()))


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    permissions: frozenset[str]
    auth_type: str


class FixedWindowLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int) -> None:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                raise AppError("RATE_LIMITED", "Too many requests", 429, f"Retry after {window_seconds} seconds")
            bucket.append(now)


rate_limiter = FixedWindowLimiter()


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    if forwarded:
        return forwarded[:64]
    return (request.client.host if request.client else "local")[:64]


def ensure_csrf(request: Request, supplied: str | None) -> None:
    expected = request.session.get("csrf_token")
    if not expected or not supplied or not hmac.compare_digest(str(expected), supplied):
        raise AppError("CSRF_FAILED", "CSRF validation failed", 403)


def ensure_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return str(token)


def authenticate_request(request: Request, db: Session) -> Principal:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        raw = auth[7:].strip()
        if not raw.startswith("cldns_") or len(raw) < 32:
            raise AppError("INVALID_TOKEN", "Invalid API token", 401)
        token = db.scalar(select(ApiToken).where(ApiToken.token_hash == token_digest(raw), ApiToken.enabled.is_(True)))
        if token is None:
            raise AppError("INVALID_TOKEN", "Invalid API token", 401)
        now = datetime.now(timezone.utc)
        if token.expires_at is not None:
            expires = token.expires_at if token.expires_at.tzinfo else token.expires_at.replace(tzinfo=timezone.utc)
            if expires <= now:
                raise AppError("TOKEN_EXPIRED", "API token has expired", 401)
        user = db.get(User, token.user_id)
        if user is None or not user.enabled:
            raise AppError("USER_DISABLED", "User account is disabled", 403)
        requested = set(json.loads(token.permissions or "[]"))
        allowed = requested & permissions_for_user(user) & ALL_PERMISSIONS
        token.last_used = now
        db.commit()
        return Principal(user.id, user.username, frozenset(allowed), "token")
    user_id = request.session.get("user_id")
    if not user_id:
        raise AppError("UNAUTHENTICATED", "Authentication required", 401)
    user = db.get(User, int(user_id))
    if user is None or not user.enabled:
        request.session.clear()
        raise AppError("UNAUTHENTICATED", "Authentication required", 401)
    return Principal(user.id, user.username, frozenset(permissions_for_user(user)), "session")
