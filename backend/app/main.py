from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .api.router import api_router
from .config import get_settings
from .database import SessionLocal, init_db
from .errors import AppError
from .models import User
from .security import get_client_ip, rate_limiter
from .web import router as web_router
from .web_platform import router as web_platform_router

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    stream=sys.stdout,
)
logger = logging.getLogger("chrislab_dns")


@asynccontextmanager
async def lifespan(application: FastAPI):
    settings.app_data_dir.mkdir(parents=True, exist_ok=True)
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    settings.staging_dir.mkdir(parents=True, exist_ok=True)
    init_db()
    yield


app = FastAPI(
    title="ChrisLab DNS API",
    version=__version__,
    description="Production-oriented BIND9 management API with transactional validation, RBAC, audit logging and backups.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)
if settings.trusted_hosts != ("*",):
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))

PROJECT_ROOT = Path(__file__).resolve().parents[2]
app.mount("/static", StaticFiles(directory=str(PROJECT_ROOT / "frontend" / "static")), name="static")


def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; frame-ancestors 'none'"
    return response


@app.middleware("http")
async def enforce_web_two_factor(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") and not path.startswith("/static/") and path not in {"/login", "/login/totp", "/logout"}:
        user_id = request.session.get("user_id")
        if user_id and not request.session.get("totp_verified"):
            try:
                with SessionLocal() as db:
                    user = db.get(User, int(user_id))
                    if user is not None and user.enabled and user.totp_enabled:
                        return RedirectResponse("/login/totp", status_code=303)
            except (TypeError, ValueError):
                request.session.clear()
                return RedirectResponse("/login", status_code=303)
    return await call_next(request)


@app.middleware("http")
async def security_headers_and_rate_limit(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        try:
            rate_limiter.check(f"api:{get_client_ip(request)}", 300, 60)
        except AppError as exc:
            response = JSONResponse(
                status_code=exc.status_code,
                content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}},
                headers={"Retry-After": "60"} if exc.status_code == 429 else None,
            )
            return _security_headers(response)
    response = await call_next(request)
    return _security_headers(response)


@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    if exc.code == "WEB_LOGIN_REQUIRED" and not request.url.path.startswith("/api/"):
        return RedirectResponse("/login", status_code=303)
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}})
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"error": {"code": "VALIDATION_ERROR", "message": "Request validation failed", "details": jsonable_encoder(exc.errors(), custom_encoder={Exception: str})}})


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": f"HTTP_{exc.status_code}", "message": str(exc.detail), "details": None}},
            headers=exc.headers,
        )
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": f"HTTP_{exc.status_code}", "message": str(exc.detail), "details": None}})


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    logger.error("Unhandled request failure path=%s", request.url.path, exc_info=(type(exc), exc, exc.__traceback__))
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_ERROR", "message": "Internal server error", "details": None}},
    )


# SessionMiddleware must wrap custom web middleware because the 2FA guard reads
# request.session before forwarding the request. FastAPI/Starlette prepend newly
# added middleware, so register sessions after the decorator-based middleware.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    max_age=settings.session_max_age,
    same_site=settings.session_samesite,
    https_only=settings.session_secure,
    session_cookie="chrislab_dns_session",
)

app.include_router(api_router)
app.include_router(web_platform_router)
app.include_router(web_router)
