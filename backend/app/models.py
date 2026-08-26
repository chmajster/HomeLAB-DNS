from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="read_only", index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    theme: Mapped[str] = mapped_column(String(16), default="system")
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_recovery_codes: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    tokens: Mapped[list[ApiToken]] = relationship(back_populates="user", cascade="all, delete-orphan")


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(24), index=True)
    permissions: Mapped[str] = mapped_column(Text, default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user: Mapped[User] = relationship(back_populates="tokens")


class Zone(Base):
    __tablename__ = "zones"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    zone_type: Mapped[str] = mapped_column(String(32), default="primary")
    reverse: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    managed: Mapped[bool] = mapped_column(Boolean, default=True)
    file_name: Mapped[str] = mapped_column(String(255), unique=True)
    source_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    default_ttl: Mapped[int] = mapped_column(Integer, default=3600)
    soa_mname: Mapped[str] = mapped_column(String(255))
    soa_rname: Mapped[str] = mapped_column(String(255))
    serial: Mapped[int] = mapped_column(Integer)
    refresh: Mapped[int] = mapped_column(Integer, default=3600)
    retry: Mapped[int] = mapped_column(Integer, default=900)
    expire: Mapped[int] = mapped_column(Integer, default=1209600)
    minimum: Mapped[int] = mapped_column(Integer, default=300)
    version: Mapped[int] = mapped_column(Integer, default=1)
    validation_status: Mapped[str] = mapped_column(String(32), default="valid")
    primary_servers: Mapped[list[str]] = mapped_column(JSON, default=list)
    allow_transfer: Mapped[list[str]] = mapped_column(JSON, default=list)
    also_notify: Mapped[list[str]] = mapped_column(JSON, default=list)
    tsig_key_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_modified: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    records: Mapped[list[Record]] = relationship(back_populates="zone", cascade="all, delete-orphan", order_by="Record.id")


class Record(Base):
    __tablename__ = "records"
    __table_args__ = (UniqueConstraint("zone_id", "name", "type", "value", "ttl", "priority", "weight", "port", name="uq_record_exact"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(Text)
    ttl: Mapped[int] = mapped_column(Integer, default=3600)
    priority: Mapped[int | None] = mapped_column(Integer, nullable=True)
    weight: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    zone: Mapped[Zone] = relationship(back_populates="records")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(120), default="system")
    ip: Mapped[str] = mapped_column(String(64), default="local")
    action: Mapped[str] = mapped_column(String(80), index=True)
    zone: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    record: Mapped[str | None] = mapped_column(String(512), nullable=True)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str] = mapped_column(String(32), index=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)


class Backup(Base):
    __tablename__ = "backups"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), unique=True)
    reason: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)


class AppState(Base):
    __tablename__ = "app_state"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class DnsServer(Base):
    __tablename__ = "dns_servers"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    address: Mapped[str] = mapped_column(String(255), index=True)
    role: Mapped[str] = mapped_column(String(32), default="secondary", index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    tsig_key_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TsigKey(Base):
    __tablename__ = "tsig_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    algorithm: Mapped[str] = mapped_column(String(32), default="hmac-sha256")
    secret_encrypted: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ZoneRevision(Base):
    __tablename__ = "zone_revisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    zone_name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[int] = mapped_column(Integer)
    serial: Mapped[int] = mapped_column(Integer)
    snapshot_json: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
