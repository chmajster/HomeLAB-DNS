#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import grp
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

CONFIG_FILE = Path("/etc/bind9-web-manager-helper.conf")
DEFAULT_BACKUP_SIGNING_KEY = Path("/var/lib/bind9-web-manager-helper/backup-signing.key")
ZONE_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$", re.IGNORECASE)
SAFE_FILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")
LOG_LEVELS = {"debug", "info", "notice", "warning", "err", "crit"}


class HelperError(RuntimeError):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


def load_config() -> dict[str, str]:
    if not CONFIG_FILE.is_file():
        raise HelperError(f"Missing helper configuration: {CONFIG_FILE}")
    stat = CONFIG_FILE.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        raise HelperError("Helper configuration must be root-owned and not group/world writable")
    data: dict[str, str] = {}
    for raw in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    required = {"BIND_ROOT", "BIND_CONFIG", "BIND_MANAGED_CONFIG", "BIND_ZONE_DIR", "BACKUP_DIR", "STAGING_DIR", "APP_USER"}
    missing = required - data.keys()
    if missing:
        raise HelperError("Missing helper settings: " + ", ".join(sorted(missing)))
    return data


def run(command: list[str], timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HelperError(str(exc)) from exc
    if check and proc.returncode != 0:
        raise HelperError((proc.stderr or proc.stdout or "Command failed").strip(), proc.returncode or 1)
    return proc


def require_zone_name(value: str) -> str:
    zone = value.rstrip(".").lower()
    if not ZONE_RE.fullmatch(zone) or ".." in zone:
        raise HelperError("Invalid zone name", 2)
    return zone


def within(path: Path, root: Path) -> bool:
    resolved = path.resolve(strict=False)
    root_resolved = root.resolve(strict=False)
    return resolved == root_resolved or root_resolved in resolved.parents


def require_existing_file(path: str, root: Path) -> Path:
    value = Path(path)
    if not within(value, root) or not value.is_file() or value.is_symlink():
        raise HelperError("Path is outside the allowed directory or is not a regular file", 2)
    return value.resolve()


def require_target_name(name: str) -> str:
    if "/" in name or "\\" in name or name in {".", ".."} or not SAFE_FILE_RE.fullmatch(name):
        raise HelperError("Invalid target filename", 2)
    return name


def bind_group_id() -> int:
    try:
        return grp.getgrnam("bind").gr_gid
    except KeyError:
        return 0


def app_ids(config: dict[str, str]) -> tuple[int, int]:
    entry = pwd.getpwnam(config["APP_USER"])
    return entry.pw_uid, entry.pw_gid


def load_backup_signing_key(config: dict[str, str]) -> bytes:
    path = Path(config.get("BACKUP_SIGNING_KEY", str(DEFAULT_BACKUP_SIGNING_KEY)))
    if not path.is_file() or path.is_symlink():
        raise HelperError("Backup signing key is missing", 2)
    meta = path.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o077:
        raise HelperError("Backup signing key must be root-owned and mode 0600", 2)
    raw = path.read_text(encoding="ascii").strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise HelperError("Backup signing key is invalid", 2) from exc
    if len(key) < 32:
        raise HelperError("Backup signing key is too short", 2)
    return key


def file_hmac(path: Path, key: bytes) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(131072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_untrusted_file(path_text: str, allowed_root: Path, destination: Path, max_bytes: int = 64 * 1024 * 1024) -> None:
    value = Path(path_text)
    root = allowed_root.resolve(strict=True)
    try:
        parent = value.parent.resolve(strict=True)
    except OSError as exc:
        raise HelperError("Invalid source directory", 2) from exc
    if parent != root or not SAFE_FILE_RE.fullmatch(value.name):
        raise HelperError("Source file must be a direct regular file in the allowed directory", 2)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(value.name, flags, dir_fd=root_fd)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_size > max_bytes:
                raise HelperError("Source is not a permitted regular file", 2)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(fd, "rb", closefd=False) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)
                target.flush()
                os.fsync(target.fileno())
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def atomic_copy_to_untrusted_dir(source: Path, target: Path, config: dict[str, str]) -> None:
    backup_root = Path(config["BACKUP_DIR"]).resolve(strict=True)
    parent = target.parent
    if target.name not in {"bind.tar.gz", "bind.tar.gz.sig"}:
        raise HelperError("Invalid backup output filename", 2)
    if parent.is_symlink() or not parent.is_dir():
        raise HelperError("Invalid backup output directory", 2)
    resolved_parent = parent.resolve(strict=True)
    if resolved_parent.parent != backup_root:
        raise HelperError("Backup output must be in a direct temporary child of BACKUP_DIR", 2)
    uid, gid = app_ids(config)
    parent_fd = os.open(resolved_parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    temp_name = f".{target.name}.{secrets.token_hex(8)}"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        try:
            with source.open("rb") as src, os.fdopen(fd, "wb", closefd=False) as dst:
                shutil.copyfileobj(src, dst)
                dst.flush()
                os.fsync(dst.fileno())
            os.fchmod(fd, 0o640)
            os.fchown(fd, uid, gid)
        finally:
            os.close(fd)
        os.replace(temp_name, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name, dir_fd=parent_fd)
        os.close(parent_fd)


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_copy(source: Path, target: Path, mode: int = 0o640, uid: int = 0, gid: int | None = None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temp = Path(temp_name)
    try:
        with source.open("rb") as src, os.fdopen(fd, "wb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(temp, mode)
        os.chown(temp, uid, bind_group_id() if gid is None else gid)
        os.replace(temp, target)
        fsync_directory(target.parent)
    finally:
        temp.unlink(missing_ok=True)


def service_name() -> str:
    for name in ("bind9", "named"):
        proc = run(["systemctl", "show", name, "--property=LoadState", "--value"], check=False)
        if proc.returncode == 0 and proc.stdout.strip() not in {"", "not-found"}:
            return name
    return "bind9"


def validate_zone(zone: str, path: Path) -> str:
    return run(["named-checkzone", zone, str(path)], timeout=30).stdout.strip()


def validate_config(path: Path, load_zones: bool = False) -> str:
    command = ["named-checkconf"]
    if load_zones:
        command.append("-z")
    command.append(str(path))
    proc = run(command, timeout=45)
    return (proc.stdout + proc.stderr).strip()


def reload_bind(zone: str | None = None) -> None:
    run(["rndc", "reconfig"], timeout=30)
    if zone:
        run(["rndc", "reload", zone], timeout=30)
    else:
        run(["rndc", "reload"], timeout=30)
    run(["systemctl", "is-active", "--quiet", service_name()], timeout=15)
    run(["rndc", "status"], timeout=15)


def snapshot_file(path: Path, root: Path) -> Path | None:
    if not path.exists():
        return None
    target = root / path.name
    shutil.copy2(path, target)
    return target


def restore_file(snapshot: Path | None, target: Path) -> None:
    if snapshot is None:
        target.unlink(missing_ok=True)
        fsync_directory(target.parent)
        return
    atomic_copy(snapshot, target)


def cmd_validate_zone(args, config):
    zone = require_zone_name(args.zone)
    with tempfile.TemporaryDirectory(prefix="bind-validate-zone-") as temp_raw:
        staged = Path(temp_raw) / "zone"
        snapshot_untrusted_file(args.file, Path(config["STAGING_DIR"]), staged, max_bytes=8 * 1024 * 1024)
        print(validate_zone(zone, staged))


def cmd_validate_config(args, config):
    print(validate_config(Path(config["BIND_CONFIG"])))


def validate_candidate_tree(config: dict[str, str], staged_managed: Path, staged_zone: Path | None = None, target_name: str | None = None, remove_target: bool = False) -> None:
    active_root = Path(config["BIND_ROOT"]).resolve()
    managed = Path(config["BIND_MANAGED_CONFIG"]).resolve(strict=False)
    zone_dir = Path(config["BIND_ZONE_DIR"]).resolve(strict=False)
    bind_config = Path(config["BIND_CONFIG"]).resolve(strict=False)
    for required_path in (managed, zone_dir, bind_config):
        if not within(required_path, active_root):
            raise HelperError("Managed BIND paths must be inside BIND_ROOT", 2)
    with tempfile.TemporaryDirectory(prefix="bind-candidate-") as temp_raw:
        candidate_root = Path(temp_raw) / "bind"
        shutil.copytree(active_root, candidate_root, symlinks=False)
        managed_candidate = candidate_root / managed.relative_to(active_root)
        managed_candidate.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged_managed, managed_candidate)
        if target_name:
            target_candidate = candidate_root / zone_dir.relative_to(active_root) / target_name
            target_candidate.parent.mkdir(parents=True, exist_ok=True)
            if remove_target:
                target_candidate.unlink(missing_ok=True)
            elif staged_zone is not None:
                shutil.copy2(staged_zone, target_candidate)
        rewrite_candidate_paths(candidate_root, active_root)
        validate_config(candidate_root / bind_config.relative_to(active_root), load_zones=True)


def cmd_validate_candidate(args, config):
    zone = require_zone_name(args.zone)
    target_name = require_target_name(args.target)
    if target_name != f"db.{zone}":
        raise HelperError("Target filename does not match zone name", 2)
    staging = Path(config["STAGING_DIR"])
    with tempfile.TemporaryDirectory(prefix="bind-validate-candidate-") as temp_raw:
        root = Path(temp_raw)
        staged_managed = root / "managed.conf"
        snapshot_untrusted_file(args.staged_managed, staging, staged_managed, max_bytes=8 * 1024 * 1024)
        staged_zone = None
        if not args.remove:
            if not args.staged_zone:
                raise HelperError("staged-zone is required for apply validation", 2)
            staged_zone = root / "zone"
            snapshot_untrusted_file(args.staged_zone, staging, staged_zone, max_bytes=8 * 1024 * 1024)
            validate_zone(zone, staged_zone)
        validate_candidate_tree(config, staged_managed, staged_zone=staged_zone, target_name=target_name, remove_target=args.remove)
    print("CANDIDATE_VALID")


def cmd_apply_zone(args, config):
    zone = require_zone_name(args.zone)
    target_name = require_target_name(args.target)
    if target_name != f"db.{zone}":
        raise HelperError("Target filename does not match zone name", 2)
    staging = Path(config["STAGING_DIR"])
    target = Path(config["BIND_ZONE_DIR"]) / target_name
    managed = Path(config["BIND_MANAGED_CONFIG"])
    with tempfile.TemporaryDirectory(prefix="bind-apply-") as temp_raw:
        root = Path(temp_raw)
        staged_zone = root / "zone"
        staged_managed = root / "managed.conf"
        snapshot_untrusted_file(args.staged_zone, staging, staged_zone, max_bytes=8 * 1024 * 1024)
        snapshot_untrusted_file(args.staged_managed, staging, staged_managed, max_bytes=8 * 1024 * 1024)
        validate_zone(zone, staged_zone)
        validate_config(staged_managed)
        validate_candidate_tree(config, staged_managed, staged_zone=staged_zone, target_name=target_name)
        rollback_root = root / "rollback"
        rollback_root.mkdir()
        old_zone = snapshot_file(target, rollback_root)
        old_managed = snapshot_file(managed, rollback_root)
        try:
            atomic_copy(staged_zone, target)
            atomic_copy(staged_managed, managed)
            validate_config(Path(config["BIND_CONFIG"]), load_zones=True)
            reload_bind(zone)
        except Exception as exc:
            restore_file(old_zone, target)
            restore_file(old_managed, managed)
            try:
                validate_config(Path(config["BIND_CONFIG"]), load_zones=True)
                reload_bind(None)
            except Exception as rollback_exc:
                raise HelperError(f"Apply failed: {exc}; rollback also failed: {rollback_exc}") from rollback_exc
            raise HelperError(f"Apply failed and was rolled back: {exc}") from exc
    print("APPLY_OK")


def cmd_remove_zone(args, config):
    zone = require_zone_name(args.zone)
    target_name = require_target_name(args.target)
    if target_name != f"db.{zone}":
        raise HelperError("Target filename does not match zone name", 2)
    staging = Path(config["STAGING_DIR"])
    target = Path(config["BIND_ZONE_DIR"]) / target_name
    managed = Path(config["BIND_MANAGED_CONFIG"])
    with tempfile.TemporaryDirectory(prefix="bind-remove-") as temp_raw:
        root = Path(temp_raw)
        staged_managed = root / "managed.conf"
        snapshot_untrusted_file(args.staged_managed, staging, staged_managed, max_bytes=8 * 1024 * 1024)
        validate_config(staged_managed)
        validate_candidate_tree(config, staged_managed, target_name=target_name, remove_target=True)
        rollback_root = root / "rollback"
        rollback_root.mkdir()
        old_zone = snapshot_file(target, rollback_root)
        old_managed = snapshot_file(managed, rollback_root)
        try:
            atomic_copy(staged_managed, managed)
            validate_config(Path(config["BIND_CONFIG"]), load_zones=True)
            reload_bind(None)
            target.unlink(missing_ok=True)
            fsync_directory(target.parent)
        except Exception as exc:
            restore_file(old_zone, target)
            restore_file(old_managed, managed)
            try:
                validate_config(Path(config["BIND_CONFIG"]), load_zones=True)
                reload_bind(None)
            except Exception as rollback_exc:
                raise HelperError(f"Removal failed: {exc}; rollback also failed: {rollback_exc}") from rollback_exc
            raise HelperError(f"Removal failed and was rolled back: {exc}") from exc
    print("REMOVE_OK")


def cmd_reload(args, config):
    validate_config(Path(config["BIND_CONFIG"]), load_zones=True)
    reload_bind(None)
    print("RELOAD_OK")


def cmd_restart(args, config):
    validate_config(Path(config["BIND_CONFIG"]), load_zones=True)
    service = service_name()
    run(["systemctl", "restart", service], timeout=60)
    run(["systemctl", "is-active", "--quiet", service], timeout=15)
    run(["rndc", "status"], timeout=15)
    print("RESTART_OK")


def read_query_statistics() -> dict[str, int] | None:
    run(["rndc", "stats"], timeout=15, check=False)
    for candidate in (Path("/var/cache/bind/named.stats"), Path("/var/lib/bind/named.stats")):
        if not candidate.is_file():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        start = 0
        for index, line in enumerate(lines):
            if line.startswith("+++ Statistics Dump +++"):
                start = index
        section = ""
        result: dict[str, int] = {}
        for line in lines[start:]:
            stripped = line.strip()
            if stripped.startswith("++ ") and stripped.endswith(" ++"):
                section = stripped[3:-3]
                continue
            if section not in {"Incoming Requests", "Incoming Queries"}:
                continue
            parts = stripped.split()
            if len(parts) != 2 or not parts[1].isdigit():
                continue
            key = ("request_" if section == "Incoming Requests" else "query_") + parts[0].lower()
            result[key] = int(parts[1])
        return result or None
    return None


def cmd_status(args, config):
    service = service_name()
    props = run(["systemctl", "show", service, "--property=ActiveState,MainPID,ActiveEnterTimestampMonotonic", "--no-pager"], check=False)
    values = {}
    for line in props.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    active = values.get("ActiveState") == "active"
    pid = int(values.get("MainPID", "0") or 0) or None
    entered_us = int(values.get("ActiveEnterTimestampMonotonic", "0") or 0)
    uptime_seconds = None
    if active and entered_us:
        try:
            boot_seconds = float(Path("/proc/uptime").read_text().split()[0])
            uptime_seconds = max(0, int(boot_seconds - entered_us / 1_000_000))
        except (OSError, ValueError, IndexError):
            uptime_seconds = None
    version_proc = run(["named", "-v"], check=False)
    rndc = run(["rndc", "status"], check=False)
    zones = recursive_clients = None
    for line in rndc.stdout.splitlines():
        lower = line.lower()
        if lower.startswith("number of zones:"):
            try: zones = int(line.split(":", 1)[1].strip())
            except ValueError: zones = None
        if lower.startswith("recursive clients:"):
            try: recursive_clients = int(line.split(":", 1)[1].split("/", 1)[0].strip())
            except ValueError: recursive_clients = None
    print(json.dumps({"active": active, "service": service, "pid": pid, "uptime_seconds": uptime_seconds, "version": version_proc.stdout.strip() or version_proc.stderr.strip(), "zones": zones, "recursive_clients": recursive_clients, "query_statistics": read_query_statistics(), "rndc_status": rndc.stdout.strip()}))


def cmd_logs(args, config):
    if args.level not in LOG_LEVELS:
        raise HelperError("Invalid log level", 2)
    if not (1 <= args.lines <= 2000 and 1 <= args.since_minutes <= 10080):
        raise HelperError("Log bounds exceeded", 2)
    proc = run(["journalctl", "-u", service_name(), "--since", f"-{args.since_minutes} minutes", "-n", str(args.lines), "-p", args.level, "--no-pager", "-o", "short-iso"], timeout=30, check=False)
    if proc.returncode not in {0, 1}:
        raise HelperError(proc.stderr.strip() or "journalctl failed", proc.returncode)
    print(proc.stdout.rstrip())


def allowed_bind_roots(config: dict[str, str]) -> list[Path]:
    return [Path(value.strip()).resolve(strict=False) for value in config.get("ALLOWED_BIND_READ_ROOTS", "/etc/bind,/var/lib/bind,/var/cache/bind").split(",") if value.strip()]


def copy_entry_dereferenced(source: Path, target: Path, roots: list[Path], ancestors: frozenset[Path] = frozenset()) -> None:
    resolved = source.resolve(strict=True) if source.is_symlink() else source.resolve(strict=True)
    if not any(within(resolved, root) for root in roots):
        raise HelperError(f"BIND backup source escapes allowed roots: {source}", 2)
    if resolved.is_dir():
        if resolved in ancestors:
            raise HelperError(f"Symlink/directory cycle detected while backing up {source}", 2)
        target.mkdir(parents=True, exist_ok=True)
        for child in resolved.iterdir():
            copy_entry_dereferenced(child, target / child.name, roots, ancestors | {resolved})
    elif resolved.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(resolved, target, follow_symlinks=True)
    else:
        raise HelperError(f"Unsupported BIND backup entry: {source}", 2)


def reject_symlinks(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise HelperError("Restore source contains symbolic links", 2)


def sync_restore_tree(source: Path, destination: Path) -> None:
    reject_symlinks(source)
    destination.mkdir(parents=True, exist_ok=True)
    gid = bind_group_id()
    for item in source.iterdir():
        target = destination / item.name
        if item.is_dir():
            if target.exists() and (not target.is_dir() or target.is_symlink()):
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=True)
            target.mkdir(parents=True, exist_ok=True)
            os.chown(target, 0, gid)
            os.chmod(target, 0o750)
            sync_restore_tree(item, target)
        elif item.is_file():
            if target.exists() and target.is_dir():
                shutil.rmtree(target)
            atomic_copy(item, target, mode=0o640, uid=0, gid=gid)
        else:
            raise HelperError("Restore source contains an unsupported entry", 2)


def is_sensitive_bind_file(path: Path) -> bool:
    lowered = path.name.lower()
    return lowered in {"rndc.key", "session.key"} or path.suffix.lower() in {".private", ".pem", ".p12", ".pfx"}


def copy_bind_entry_for_backup(
    source: Path,
    target: Path,
    roots: list[Path],
    declared_zone_files: set[Path],
    ancestors: frozenset[Path] = frozenset(),
) -> None:
    resolved = source.resolve(strict=True)
    if not any(within(resolved, root) for root in roots):
        raise HelperError(f"BIND backup source escapes allowed roots: {source}", 2)
    if resolved.is_dir():
        if resolved in ancestors:
            raise HelperError(f"Symlink/directory cycle detected while backing up {source}", 2)
        target.mkdir(parents=True, exist_ok=True)
        for child in resolved.iterdir():
            copy_bind_entry_for_backup(child, target / child.name, roots, declared_zone_files, ancestors | {resolved})
    elif resolved.is_file():
        if is_sensitive_bind_file(resolved) and resolved not in declared_zone_files:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(resolved, target, follow_symlinks=True)
    else:
        raise HelperError(f"Unsupported BIND backup entry: {source}", 2)


def declared_zone_files(config: dict[str, str]) -> dict[Path, dict[str, str]]:
    roots = allowed_bind_roots(config)
    result: dict[Path, dict[str, str]] = {}
    for entry in discover_zone_entries(config):
        path_text = entry.get("file", "")
        if not path_text:
            continue
        try:
            resolved = Path(path_text).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file() and any(within(resolved, root) for root in roots):
            result[resolved] = entry
    return result


def safe_extract_signed_backup(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        root = destination.resolve()
        for member in tar.getmembers():
            candidate = (destination / member.name).resolve(strict=False)
            if root not in candidate.parents and candidate != root:
                raise HelperError("Signed BIND backup contains an unsafe path", 2)
            if member.isdev() or member.isfifo() or member.issym() or member.islnk():
                raise HelperError("Signed BIND backup contains an unsupported special entry", 2)
            if member.isdir():
                candidate.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                candidate.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise HelperError("Signed BIND backup member cannot be read", 2)
                with source, candidate.open("wb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(candidate, member.mode & 0o777)
            else:
                raise HelperError("Signed BIND backup contains an unsupported entry", 2)


def cmd_export_bind(args, config):
    dest = Path(args.dest)
    if dest.name != "bind.tar.gz":
        raise HelperError("BIND backup destination must be named bind.tar.gz", 2)
    bind_root = Path(config["BIND_ROOT"]).resolve(strict=True)
    roots = allowed_bind_roots(config)
    zones = declared_zone_files(config)
    with tempfile.TemporaryDirectory(prefix="bind-export-") as temp_raw:
        root = Path(temp_raw)
        payload = root / "payload"
        bind_copy = payload / "bind"
        bind_copy.mkdir(parents=True)
        for item in bind_root.iterdir():
            copy_bind_entry_for_backup(item, bind_copy / item.name, roots, set(zones))
        external_dir = payload / "external-zones"
        external_dir.mkdir()
        zone_manifest: list[dict[str, object]] = []
        external_index = 0
        for zone_path, entry in sorted(zones.items(), key=lambda item: str(item[0])):
            if within(zone_path, bind_root):
                archive_rel = "bind/" + zone_path.relative_to(bind_root).as_posix()
                external = False
            else:
                external_index += 1
                archive_name = f"{external_index:06d}.zone"
                shutil.copy2(zone_path, external_dir / archive_name)
                archive_rel = f"external-zones/{archive_name}"
                external = True
            zone_manifest.append({
                "archive": archive_rel,
                "target": str(zone_path),
                "name": entry.get("name", ""),
                "type": entry.get("type", ""),
                "external": external,
            })
        manifest = {"format": 1, "zones": zone_manifest}
        (payload / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
        archive = root / "bind.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for item in sorted(payload.iterdir(), key=lambda value: value.name):
                tar.add(item, arcname=item.name, recursive=True)
        key = load_backup_signing_key(config)
        signature = root / "bind.tar.gz.sig"
        signature.write_text(file_hmac(archive, key) + "\n", encoding="ascii")
        atomic_copy_to_untrusted_dir(archive, dest, config)
        atomic_copy_to_untrusted_dir(signature, Path(str(dest) + ".sig"), config)
    print("EXPORT_OK")


def rewrite_candidate_paths(root: Path, active_root: Path) -> None:
    old = str(active_root).rstrip("/") + "/"
    new = str(root).rstrip("/") + "/"
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name.startswith("named.conf") or path.suffix == ".conf":
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if old in text:
                path.write_text(text.replace(old, new), encoding="utf-8")


def validate_backup_tree(source: Path, active_root: Path) -> None:
    reject_symlinks(source)
    with tempfile.TemporaryDirectory(prefix="bind-restore-validate-") as temp_raw:
        candidate = Path(temp_raw) / "bind"
        shutil.copytree(source, candidate, symlinks=False)
        rewrite_candidate_paths(candidate, active_root)
        validate_config(candidate / "named.conf", load_zones=False)


def backup_zone_entries(manifest: dict[str, object]) -> list[dict[str, object]]:
    entries = manifest.get("zones", [])
    if not isinstance(entries, list):
        raise HelperError("Signed BIND backup manifest is invalid", 2)
    normalized: list[dict[str, object]] = []
    for raw in entries:
        if not isinstance(raw, dict):
            raise HelperError("Signed BIND backup manifest is invalid", 2)
        normalized.append(raw)
    return normalized


def validate_backup_zones(payload: Path, manifest: dict[str, object]) -> None:
    root = payload.resolve()
    for raw in backup_zone_entries(manifest):
        zone_type = str(raw.get("type", "")).lower()
        zone_name = str(raw.get("name", "")).rstrip(".")
        if zone_type not in {"master", "primary"} or not zone_name:
            continue
        archive_rel = str(raw.get("archive", ""))
        archive_file = (payload / archive_rel).resolve(strict=True)
        if root not in archive_file.parents or not archive_file.is_file():
            raise HelperError("Signed BIND backup zone entry is invalid", 2)
        validate_zone(require_zone_name(zone_name), archive_file)


def restore_external_zones(payload: Path, manifest: dict[str, object], config: dict[str, str], safety_root: Path) -> list[tuple[Path, Path | None]]:
    roots = allowed_bind_roots(config)
    snapshots: list[tuple[Path, Path | None]] = []
    payload_root = payload.resolve()
    safety_root.mkdir(parents=True, exist_ok=True)
    for index, raw in enumerate(backup_zone_entries(manifest)):
        if not bool(raw.get("external", False)):
            continue
        archive_rel = str(raw.get("archive", ""))
        target_text = str(raw.get("target", ""))
        archive_file = (payload / archive_rel).resolve(strict=True)
        if payload_root not in archive_file.parents or not archive_file.is_file():
            raise HelperError("Signed BIND backup external zone entry is invalid", 2)
        target = Path(target_text).resolve(strict=False)
        if not any(within(target, root) for root in roots):
            raise HelperError("Signed BIND backup external zone target is outside allowed roots", 2)
        snapshot_dir = safety_root / f"{index:06d}"
        snapshot_dir.mkdir()
        snapshot = snapshot_file(target, snapshot_dir) if target.exists() else None
        snapshots.append((target, snapshot))
        atomic_copy(archive_file, target, mode=0o640, uid=0, gid=bind_group_id())
    return snapshots


def rollback_external_zones(snapshots: list[tuple[Path, Path | None]]) -> None:
    for target, snapshot in snapshots:
        restore_file(snapshot, target)


def cmd_restore_bind(args, config):
    source = Path(args.source)
    if source.name != "bind.tar.gz":
        raise HelperError("Invalid BIND backup source filename", 2)
    backup_root = Path(config["BACKUP_DIR"]).resolve(strict=True)
    if source.parent.is_symlink() or not source.parent.is_dir() or source.parent.resolve(strict=True).parent != backup_root:
        raise HelperError("BIND backup source must be in a direct temporary child of BACKUP_DIR", 2)
    with tempfile.TemporaryDirectory(prefix="bind-restore-") as temp_raw:
        root = Path(temp_raw)
        archive = root / "bind.tar.gz"
        signature = root / "bind.tar.gz.sig"
        snapshot_untrusted_file(str(source), source.parent, archive, max_bytes=256 * 1024 * 1024)
        snapshot_untrusted_file(str(source) + ".sig", source.parent, signature, max_bytes=4096)
        expected = signature.read_text(encoding="ascii").strip().lower()
        actual = file_hmac(archive, load_backup_signing_key(config))
        if not hmac.compare_digest(expected, actual):
            raise HelperError("BIND backup signature verification failed", 2)
        payload = root / "payload"
        payload.mkdir()
        safe_extract_signed_backup(archive, payload)
        bind_source = payload / "bind"
        manifest_file = payload / "manifest.json"
        if not bind_source.is_dir() or not (bind_source / "named.conf").is_file() or not manifest_file.is_file():
            raise HelperError("Signed BIND backup is incomplete", 2)
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HelperError("Signed BIND backup manifest is invalid", 2) from exc
        if not isinstance(manifest, dict) or manifest.get("format") != 1:
            raise HelperError("Unsupported signed BIND backup format", 2)
        bind_root = Path(config["BIND_ROOT"]).resolve(strict=True)
        validate_backup_tree(bind_source, bind_root)
        validate_backup_zones(payload, manifest)
        safety = root / "safety-bind"
        safety.mkdir()
        roots = allowed_bind_roots(config)
        for item in bind_root.iterdir():
            copy_entry_dereferenced(item, safety / item.name, roots)
        external_snapshots: list[tuple[Path, Path | None]] = []
        try:
            sync_restore_tree(bind_source, bind_root)
            external_snapshots = restore_external_zones(payload, manifest, config, root / "safety-external")
            validate_config(Path(config["BIND_CONFIG"]), load_zones=True)
            reload_bind(None)
        except Exception as exc:
            sync_restore_tree(safety, bind_root)
            rollback_external_zones(external_snapshots)
            try:
                validate_config(Path(config["BIND_CONFIG"]), load_zones=True)
                reload_bind(None)
            except Exception as rollback_exc:
                raise HelperError(f"Restore failed: {exc}; rollback also failed: {rollback_exc}") from rollback_exc
            raise HelperError(f"Restore failed and was rolled back: {exc}") from exc
    print("RESTORE_OK")


def extract_zone_blocks(text: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    cursor = 0
    pattern = re.compile(r'\bzone\s+"([^"]+)"\s*\{', re.IGNORECASE)
    while True:
        match = pattern.search(text, cursor)
        if not match:
            return results
        depth = 1
        index = match.end()
        in_string = False
        escaped = False
        while index < len(text) and depth:
            char = text[index]
            if in_string:
                if escaped: escaped = False
                elif char == "\\": escaped = True
                elif char == '"': in_string = False
            else:
                if char == '"': in_string = True
                elif char == "{": depth += 1
                elif char == "}": depth -= 1
            index += 1
        if depth != 0:
            raise HelperError("Unable to parse named-checkconf output")
        results.append((match.group(1), text[match.end():index - 1]))
        cursor = index


def discover_zone_entries(config: dict[str, str]) -> list[dict[str, str]]:
    proc = run(["named-checkconf", "-p", config["BIND_CONFIG"]], timeout=45)
    directory_match = re.search(r'\bdirectory\s+"([^"]+)"\s*;', proc.stdout, re.IGNORECASE)
    working_directory = Path(directory_match.group(1)) if directory_match else Path("/var/cache/bind")
    output: list[dict[str, str]] = []
    for name, block in extract_zone_blocks(proc.stdout):
        type_match = re.search(r"\btype\s+([A-Za-z]+)\s*;", block)
        file_match = re.search(r'\bfile\s+"([^"]+)"\s*;', block)
        if not type_match or not file_match:
            continue
        file_path = Path(file_match.group(1))
        if not file_path.is_absolute():
            file_path = working_directory / file_path
        output.append({"name": name.rstrip("."), "type": type_match.group(1).lower(), "file": str(file_path)})
    return output


def cmd_discover_zones(args, config):
    print(json.dumps(discover_zone_entries(config)))


def cmd_read_zone(args, config):
    requested = Path(args.file).resolve(strict=True)
    roots = allowed_bind_roots(config)
    declared: set[Path] = set()
    for entry in discover_zone_entries(config):
        try:
            candidate = Path(entry["file"]).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if any(within(candidate, root) for root in roots):
            declared.add(candidate)
    if requested not in declared or not requested.is_file():
        raise HelperError("The requested file is not a declared BIND zone file", 2)
    if requested.stat().st_size > 8 * 1024 * 1024:
        raise HelperError("Zone file exceeds 8 MiB", 2)
    sys.stdout.write(requested.read_text(encoding="utf-8"))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Restricted privileged helper for ChrisLab-DNS")
    sub = root.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate-zone"); p.add_argument("--zone", required=True); p.add_argument("--file", required=True); p.set_defaults(func=cmd_validate_zone)
    p = sub.add_parser("validate-config"); p.set_defaults(func=cmd_validate_config)
    p = sub.add_parser("validate-candidate"); p.add_argument("--zone", required=True); p.add_argument("--staged-zone"); p.add_argument("--target", required=True); p.add_argument("--staged-managed", required=True); p.add_argument("--remove", action="store_true"); p.set_defaults(func=cmd_validate_candidate)
    p = sub.add_parser("apply-zone"); p.add_argument("--zone", required=True); p.add_argument("--staged-zone", required=True); p.add_argument("--target", required=True); p.add_argument("--staged-managed", required=True); p.set_defaults(func=cmd_apply_zone)
    p = sub.add_parser("remove-zone"); p.add_argument("--zone", required=True); p.add_argument("--target", required=True); p.add_argument("--staged-managed", required=True); p.set_defaults(func=cmd_remove_zone)
    p = sub.add_parser("reload"); p.set_defaults(func=cmd_reload)
    p = sub.add_parser("restart"); p.set_defaults(func=cmd_restart)
    p = sub.add_parser("status"); p.set_defaults(func=cmd_status)
    p = sub.add_parser("logs"); p.add_argument("--lines", type=int, default=200); p.add_argument("--since-minutes", type=int, default=60); p.add_argument("--level", default="info"); p.set_defaults(func=cmd_logs)
    p = sub.add_parser("export-bind"); p.add_argument("--dest", required=True); p.set_defaults(func=cmd_export_bind)
    p = sub.add_parser("restore-bind"); p.add_argument("--source", required=True); p.set_defaults(func=cmd_restore_bind)
    p = sub.add_parser("discover-zones"); p.set_defaults(func=cmd_discover_zones)
    p = sub.add_parser("read-zone"); p.add_argument("--file", required=True); p.set_defaults(func=cmd_read_zone)
    return root


def main() -> int:
    if os.geteuid() != 0:
        print("Helper must run as root", file=sys.stderr)
        return 1
    try:
        config = load_config()
        args = parser().parse_args()
        args.func(args, config)
        return 0
    except HelperError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except Exception as exc:
        print(f"Unexpected helper error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
