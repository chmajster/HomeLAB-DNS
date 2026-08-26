from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import MetaData, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_settings


class Base(DeclarativeBase):
    metadata = MetaData()


def _make_engine():
    settings = get_settings()
    kwargs: dict[str, object] = {"pool_pre_ping": True}
    if settings.database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if settings.database_url in {"sqlite://", "sqlite:///:memory:"}:
            kwargs["poolclass"] = StaticPool
    return create_engine(settings.database_url, **kwargs)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def ensure_schema_columns() -> None:
    """Apply additive migrations required by upgrades from pre-0.2 databases.

    New tables are created by ``create_all``. Existing SQLAlchemy tables need
    explicit ADD COLUMN statements because ``create_all`` deliberately does not
    mutate an existing schema.
    """

    inspector = inspect(engine)
    migrations: dict[str, dict[str, str]] = {
        "users": {
            "totp_secret_encrypted": "TEXT",
            "totp_enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "totp_recovery_codes": "TEXT NOT NULL DEFAULT '[]'",
        },
        "zones": {
            "primary_servers": "JSON NOT NULL DEFAULT '[]'",
            "allow_transfer": "JSON NOT NULL DEFAULT '[]'",
            "also_notify": "JSON NOT NULL DEFAULT '[]'",
            "tsig_key_name": "VARCHAR(120)",
        },
    }
    with engine.begin() as connection:
        for table_name, columns in migrations.items():
            if not inspector.has_table(table_name):
                continue
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, ddl in columns.items():
                if column_name in existing:
                    continue
                connection.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN "{column_name}" {ddl}'))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
