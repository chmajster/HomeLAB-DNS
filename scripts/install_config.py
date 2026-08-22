#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
SAMESITE_VALUES = {"lax", "strict", "none"}


class ConfigError(ValueError):
    pass


def require_object(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a JSON object")
    return value


def reject_unknown(data: dict[str, Any], allowed: set[str], name: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"Unknown {name} option(s): {', '.join(unknown)}")


def safe_text(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    if not allow_empty and not value:
        raise ConfigError(f"{name} must not be empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConfigError(f"{name} must not contain control characters")
    return value


def absolute_path(value: Any, name: str) -> str:
    text = safe_text(value, name)
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"{name} must be an absolute path without '..'")
    if any(char.isspace() for char in text):
        raise ConfigError(f"{name} must not contain whitespace")
    return str(path)


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false")
    return value


def integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def list_of_text(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{name} must be a non-empty JSON array")
    result = [safe_text(item, f"{name}[]") for item in value]
    if len(set(result)) != len(result):
        raise ConfigError(f"{name} must not contain duplicates")
    return result


def parse_config(path: Path) -> dict[str, str]:
    try:
        raw = path.read_text(encoding="utf-8")
        document = json.loads(raw)
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ConfigError("Top-level JSON value must be an object")

    reject_unknown(document, {"app", "bind", "security", "admin", "installation"}, "top-level")
    app = require_object(document.get("app"), "app")
    bind = require_object(document.get("bind"), "bind")
    security = require_object(document.get("security"), "security")
    admin = require_object(document.get("admin"), "admin")
    installation = require_object(document.get("installation"), "installation")

    reject_unknown(app, {"host", "port", "data_dir"}, "app")
    reject_unknown(bind, {"config", "local_config", "managed_config", "zone_dir", "allowed_read_roots"}, "bind")
    reject_unknown(security, {"session_secure", "session_samesite", "session_max_age", "auto_backup", "trusted_hosts", "log_level"}, "security")
    reject_unknown(admin, {"username", "password", "password_file"}, "admin")
    reject_unknown(installation, {"sync_existing", "remove_default_nginx_site"}, "installation")

    out: dict[str, str] = {}
    if "host" in app:
        host = safe_text(app["host"], "app.host")
        if host != "127.0.0.1":
            raise ConfigError("app.host must be 127.0.0.1; nginx is the public entry point")
        out["APP_HOST"] = host
    if "port" in app:
        out["APP_PORT"] = str(integer(app["port"], "app.port", 1, 65535))
    if "data_dir" in app:
        out["DATA_DIR"] = absolute_path(app["data_dir"], "app.data_dir")

    path_fields = {
        "config": "BIND_CONFIG",
        "local_config": "BIND_LOCAL_CONFIG",
        "managed_config": "BIND_MANAGED_CONFIG",
        "zone_dir": "BIND_ZONE_DIR",
    }
    for json_key, env_key in path_fields.items():
        if json_key in bind:
            value = absolute_path(bind[json_key], f"bind.{json_key}")
            if Path("/etc/bind") not in (Path(value), *Path(value).parents):
                raise ConfigError(f"bind.{json_key} must be inside /etc/bind")
            out[env_key] = value
    if "allowed_read_roots" in bind:
        roots = [absolute_path(item, "bind.allowed_read_roots[]") for item in list_of_text(bind["allowed_read_roots"], "bind.allowed_read_roots")]
        out["ALLOWED_BIND_READ_ROOTS"] = ",".join(roots)

    if "session_secure" in security:
        out["SESSION_SECURE"] = "true" if boolean(security["session_secure"], "security.session_secure") else "false"
    if "session_samesite" in security:
        samesite = safe_text(security["session_samesite"], "security.session_samesite").lower()
        if samesite not in SAMESITE_VALUES:
            raise ConfigError("security.session_samesite must be one of: lax, strict, none")
        out["SESSION_SAMESITE"] = samesite
    if "session_max_age" in security:
        out["SESSION_MAX_AGE"] = str(integer(security["session_max_age"], "security.session_max_age", 300, 604800))
    if "auto_backup" in security:
        out["AUTO_BACKUP"] = "true" if boolean(security["auto_backup"], "security.auto_backup") else "false"
    if "trusted_hosts" in security:
        out["TRUSTED_HOSTS"] = ",".join(list_of_text(security["trusted_hosts"], "security.trusted_hosts"))
    if "log_level" in security:
        level = safe_text(security["log_level"], "security.log_level").upper()
        if level not in LOG_LEVELS:
            raise ConfigError("security.log_level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")
        out["LOG_LEVEL"] = level

    if "username" in admin:
        username = safe_text(admin["username"], "admin.username")
        if not USERNAME_RE.fullmatch(username):
            raise ConfigError("admin.username contains unsupported characters")
        out["ADMIN_USERNAME"] = username
    if "password" in admin and "password_file" in admin:
        raise ConfigError("admin.password and admin.password_file are mutually exclusive")
    if "password" in admin:
        password = safe_text(admin["password"], "admin.password")
        if len(password) < 12:
            raise ConfigError("admin.password must contain at least 12 characters")
        out["ADMIN_PASSWORD"] = password
    if "password_file" in admin:
        out["ADMIN_PASSWORD_FILE"] = absolute_path(admin["password_file"], "admin.password_file")

    if "sync_existing" in installation:
        out["SYNC_EXISTING"] = "true" if boolean(installation["sync_existing"], "installation.sync_existing") else "false"
    if "remove_default_nginx_site" in installation:
        out["REMOVE_DEFAULT_NGINX_SITE"] = "true" if boolean(installation["remove_default_nginx_site"], "installation.remove_default_nginx_site") else "false"

    samesite = out.get("SESSION_SAMESITE", "lax")
    secure = out.get("SESSION_SECURE", "false") == "true"
    if samesite == "none" and not secure:
        raise ConfigError("security.session_samesite='none' requires security.session_secure=true")
    return out


def emit_nul(data: dict[str, str]) -> None:
    for key, value in data.items():
        sys.stdout.buffer.write(key.encode("utf-8") + b"\0" + value.encode("utf-8") + b"\0")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and normalize ChrisLab-DNS installation JSON")
    parser.add_argument("config", type=Path)
    parser.add_argument("--format", choices=("nul", "json"), default="nul")
    args = parser.parse_args()
    try:
        data = parse_config(args.config)
    except ConfigError as exc:
        print(f"Invalid install configuration: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        emit_nul(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
