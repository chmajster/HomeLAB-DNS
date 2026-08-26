from __future__ import annotations

import argparse
import secrets
import string
from pathlib import Path

from sqlalchemy import select

from .database import SessionLocal, ensure_schema_columns, init_db
from .errors import AppError
from .models import AppState, Backup, User
from .security import hash_password
from .services.backup import BackupService
from .services.sync import SyncService


def strong_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-+="
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value) and any(c in "!@#$%^&*_-+=" for c in value):
            return value


def read_password_file(path_text: str) -> str:
    path = Path(path_text)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Password file must be a regular file and must not be a symlink")
    if path.stat().st_size > 4096:
        raise ValueError("Password file is too large")
    password = path.read_text(encoding="utf-8").rstrip("\r\n")
    if not password:
        raise ValueError("Password file is empty")
    return password


def create_admin(username: str, password: str | None, *, only_if_admin_missing: bool = True) -> str | None:
    init_db()
    generated = password is None
    password = password or strong_password()
    with SessionLocal() as db:
        if only_if_admin_missing:
            admin_exists = db.scalar(
                select(User.id).where(User.role == "administrator", User.enabled.is_(True)).limit(1)
            )
            if admin_exists is not None:
                return None
        if db.scalar(select(User.id).where(User.username == username)) is not None:
            return None
        db.add(User(username=username, password_hash=hash_password(password), role="administrator", enabled=True))
        db.commit()
    return password if generated else ""


def migrate() -> None:
    init_db()
    ensure_schema_columns()
    with SessionLocal() as db:
        if db.get(AppState, "auth.mode") is None:
            db.add(AppState(key="auth.mode", value="local"))
        db.commit()


def sync_existing() -> list[str]:
    init_db()
    with SessionLocal() as db:
        return SyncService(db).import_missing()


def create_backup(reason: str) -> int:
    init_db()
    with SessionLocal() as db:
        row = BackupService(db).create(reason, "cli")
        db.commit()
        return row.id


def restore_backup(backup_id: int) -> None:
    init_db()
    with SessionLocal() as db:
        row = db.get(Backup, backup_id)
        if row is None:
            raise AppError("BACKUP_NOT_FOUND", "Backup not found", 404)
        service = BackupService(db)
        safety = service.create(f"CLI safety backup before restore {backup_id}", "cli")
        db.commit()
        try:
            service.restore(row)
        except Exception as exc:
            try:
                service.restore(safety)
            except Exception as rollback_exc:
                raise AppError("RESTORE_ROLLBACK_FAILED", "Restore and safety rollback both failed", 500, f"restore: {exc}; rollback: {rollback_exc}") from rollback_exc
            raise AppError("RESTORE_FAILED", "Restore failed; previous state was restored", 422, str(exc)) from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="ChrisLab-DNS maintenance CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin")
    admin.add_argument("--username", default="admin")
    admin.add_argument("--allow-additional-admin", action="store_true")
    password_group = admin.add_mutually_exclusive_group()
    password_group.add_argument("--password")
    password_group.add_argument("--password-file")
    sub.add_parser("migrate")
    sub.add_parser("sync-existing")
    backup = sub.add_parser("backup")
    backup.add_argument("--reason", default="CLI backup")
    restore = sub.add_parser("restore")
    restore.add_argument("--id", type=int, required=True)
    args = parser.parse_args()
    if args.command == "create-admin":
        password = read_password_file(args.password_file) if args.password_file else args.password
        result = create_admin(args.username, password, only_if_admin_missing=not args.allow_additional_admin)
        if result is None:
            print("ADMIN_EXISTS")
        elif result:
            print(f"ONE_TIME_ADMIN_PASSWORD={result}")
        else:
            print("ADMIN_CREATED")
    elif args.command == "migrate":
        migrate()
        print("MIGRATION_OK")
    elif args.command == "sync-existing":
        imported = sync_existing()
        print(f"SYNC_IMPORTED={len(imported)}")
        for name in imported:
            print(name)
    elif args.command == "backup":
        print(f"BACKUP_ID={create_backup(args.reason)}")
    else:
        restore_backup(args.id)
        print("RESTORE_OK")


if __name__ == "__main__":
    main()
