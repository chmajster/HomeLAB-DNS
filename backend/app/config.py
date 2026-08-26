from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _load_env_file() -> None:
    env_file = Path(os.getenv("ENV_FILE", "/etc/bind9-web-manager.env"))
    if not env_file.is_file():
        local = Path.cwd() / ".env"
        env_file = local if local.is_file() else env_file
    if not env_file.is_file():
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_host: str
    app_port: int
    app_data_dir: Path
    database_url: str
    bind_config: Path
    bind_local_config: Path
    bind_managed_config: Path
    bind_zone_dir: Path
    backup_dir: Path
    staging_dir: Path
    bind_helper: tuple[str, ...]
    dhcp_helper: tuple[str, ...]
    session_secure: bool
    session_samesite: str
    session_max_age: int
    auto_backup: bool
    secret_key: str
    trusted_hosts: tuple[str, ...]
    log_level: str
    testing: bool


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    _load_env_file()
    data_dir = Path(os.getenv("APP_DATA_DIR", "/var/lib/bind9-web-manager"))
    secret = os.getenv("SECRET_KEY", "")
    testing = _bool("TESTING", False)
    if not secret and not testing:
        raise RuntimeError("SECRET_KEY is required. Run install.sh or set it in the environment.")
    if not secret:
        secret = "test-only-secret-key-not-for-production"
    helper_raw = os.getenv("BIND_HELPER", "/usr/bin/sudo /usr/local/libexec/bind9-web-manager-helper")
    dhcp_helper_raw = os.getenv("DHCP_HELPER", "/usr/bin/sudo /usr/local/libexec/chrislab-dhcp-helper")
    return Settings(
        app_host=os.getenv("APP_HOST", "127.0.0.1"),
        app_port=int(os.getenv("APP_PORT", "8080")),
        app_data_dir=data_dir,
        database_url=os.getenv("DATABASE_URL", f"sqlite:///{data_dir / 'database.db'}"),
        bind_config=Path(os.getenv("BIND_CONFIG", "/etc/bind/named.conf")),
        bind_local_config=Path(os.getenv("BIND_LOCAL_CONFIG", "/etc/bind/named.conf.local")),
        bind_managed_config=Path(os.getenv("BIND_MANAGED_CONFIG", "/etc/bind/named.conf.chrislab")),
        bind_zone_dir=Path(os.getenv("BIND_ZONE_DIR", "/etc/bind/zones")),
        backup_dir=Path(os.getenv("BACKUP_DIR", str(data_dir / "backups"))),
        staging_dir=Path(os.getenv("STAGING_DIR", str(data_dir / "staging"))),
        bind_helper=tuple(shlex.split(helper_raw)),
        dhcp_helper=tuple(shlex.split(dhcp_helper_raw)),
        session_secure=_bool("SESSION_SECURE", True),
        session_samesite=os.getenv("SESSION_SAMESITE", "lax"),
        session_max_age=int(os.getenv("SESSION_MAX_AGE", "28800")),
        auto_backup=_bool("AUTO_BACKUP", True),
        secret_key=secret,
        trusted_hosts=tuple(x.strip() for x in os.getenv("TRUSTED_HOSTS", "*").split(",") if x.strip()),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        testing=testing,
    )
