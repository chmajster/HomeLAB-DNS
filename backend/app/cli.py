from __future__ import annotations

import argparse
import secrets
import string

from sqlalchemy import select

from .database import SessionLocal, init_db
from .errors import AppError
from .models import Backup, User
from .security import hash_password
from .services.backup import BackupService
from .services.sync import SyncService


def strong_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-+="
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value) and any(c in "!@#$%^&*_-+=" for c in value):
            return value


def create_admin(username: str, password: str | None) -> str | None:
    init_db()
    generated = password is None
    password = password or strong_password()
    with SessionLocal() as db:
        if db.scalar(select(User.id).where(User.username == username)) is not None:
            return None
        db.add(User(username=username, password_hash=hash_password(password), role="administrator", enabled=True))
        db.commit()
    return password if generated else ""


def migrate() -> None:
    init_db()


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
    admin.add_argument("--password")
    sub.add_parser("migrate")
    sub.add_parser("sync-existing")
    backup = sub.add_parser("backup")
    backup.add_argument("--reason", default="CLI backup")
    restore = sub.add_parser("restore")
    restore.add_argument("--id", type=int, required=True)
    args = parser.parse_args()
    if args.command == "create-admin":
        result = create_admin(args.username, args.password)
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
