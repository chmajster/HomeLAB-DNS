from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..errors import AppError
from ..models import Backup
from .bind import BindService


class BackupService:
    def __init__(self, db: Session, bind: BindService | None = None, settings: Settings | None = None) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.bind = bind or BindService(self.settings)

    def _sqlite_path(self) -> Path:
        prefix = "sqlite:///"
        if not self.settings.database_url.startswith(prefix):
            raise AppError("BACKUP_DATABASE_UNSUPPORTED", "File backup currently requires SQLite", 409)
        return Path(self.settings.database_url[len(prefix):])

    def create(self, reason: str, username: str) -> Backup:
        self.settings.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        filename = f"backup-{stamp}.tar.gz"
        archive = self.settings.backup_dir / filename
        with tempfile.TemporaryDirectory(prefix="backup-", dir=self.settings.backup_dir) as temp_raw:
            temp = Path(temp_raw)
            bind_archive = temp / "bind.tar.gz"
            self.bind.export_bind(bind_archive)
            bind_signature = Path(str(bind_archive) + ".sig")
            if not bind_archive.is_file() or not bind_signature.is_file():
                raise AppError("BACKUP_EXPORT_FAILED", "BIND helper did not produce a signed backup", 500)
            db_source = self._sqlite_path()
            db_copy = temp / "database.db"
            source = sqlite3.connect(str(db_source))
            target = sqlite3.connect(str(db_copy))
            try:
                source.backup(target)
            finally:
                target.close()
                source.close()
            metadata = {"reason": reason, "created_by": username, "created_at": datetime.now(timezone.utc).isoformat()}
            (temp / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
            archive_temp = archive.with_suffix(archive.suffix + ".tmp")
            try:
                with tarfile.open(archive_temp, "w:gz") as tar:
                    tar.add(temp, arcname=".")
                with archive_temp.open("rb") as handle:
                    os.fsync(handle.fileno())
                os.replace(archive_temp, archive)
                directory_fd = os.open(self.settings.backup_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                archive_temp.unlink(missing_ok=True)
        row = Backup(filename=filename, reason=reason, created_by=username, size_bytes=archive.stat().st_size)
        self.db.add(row)
        self.db.flush()
        return row

    def restore(self, backup: Backup) -> None:
        archive = (self.settings.backup_dir / backup.filename).resolve()
        root = self.settings.backup_dir.resolve()
        if root not in archive.parents or not archive.is_file():
            raise AppError("BACKUP_NOT_FOUND", "Backup file not found", 404)
        with tempfile.TemporaryDirectory(prefix="restore-", dir=self.settings.backup_dir) as temp_raw:
            temp = Path(temp_raw)
            with tarfile.open(archive, "r:gz") as tar:
                root = temp.resolve()
                for member in tar.getmembers():
                    candidate = (temp / member.name).resolve(strict=False)
                    if root not in candidate.parents and candidate != root:
                        raise AppError("BACKUP_INVALID", "Backup contains an unsafe path", 422)
                    if member.isdev() or member.isfifo() or member.islnk() or member.issym():
                        raise AppError("BACKUP_INVALID", "Backup contains an unsupported special entry", 422)
                    if member.isdir():
                        candidate.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        candidate.parent.mkdir(parents=True, exist_ok=True)
                        source = tar.extractfile(member)
                        if source is None:
                            raise AppError("BACKUP_INVALID", "Backup file entry cannot be read", 422)
                        with source, candidate.open("wb") as destination:
                            shutil.copyfileobj(source, destination)
                        os.chmod(candidate, member.mode & 0o777)
                    else:
                        raise AppError("BACKUP_INVALID", "Backup contains an unsupported entry", 422)
            bind_archive = temp / "bind.tar.gz"
            bind_signature = temp / "bind.tar.gz.sig"
            db_copy = temp / "database.db"
            if not bind_archive.is_file() or not bind_signature.is_file() or not db_copy.is_file():
                raise AppError("BACKUP_INVALID", "Backup is incomplete", 422)
            self.bind.restore_bind(bind_archive)
            db_target = self._sqlite_path()
            safety = db_target.with_suffix(db_target.suffix + ".restore-safety")
            shutil.copy2(db_target, safety)
            try:
                source = sqlite3.connect(str(db_copy))
                target = sqlite3.connect(str(db_target))
                try:
                    source.backup(target)
                finally:
                    target.close()
                    source.close()
            except Exception as exc:
                shutil.copy2(safety, db_target)
                raise AppError("DATABASE_RESTORE_FAILED", "Database restore failed", 500, str(exc)) from exc
            finally:
                safety.unlink(missing_ok=True)

    def delete(self, backup: Backup) -> None:
        path = (self.settings.backup_dir / backup.filename).resolve()
        if self.settings.backup_dir.resolve() not in path.parents:
            raise AppError("BACKUP_PATH_INVALID", "Unsafe backup path", 400)
        path.unlink(missing_ok=True)
        self.db.delete(backup)
        self.db.commit()
