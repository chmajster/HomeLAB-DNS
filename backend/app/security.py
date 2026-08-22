from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

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
