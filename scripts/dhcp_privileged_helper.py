#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

CONFIG_FILE = Path("/etc/chrislab-dhcp-helper.conf")
BACKUP_NAME_RE = re.compile(r"^kea-dhcp([46])-\d{8}T\d{6}(?:-\d{2})?Z\.json$")
UNSAFE_KEYS = {"hooks-libraries"}


class HelperError(RuntimeError):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


def run(command: list[str], timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HelperError(str(exc)) from exc
    if check and proc.returncode != 0:
        raise HelperError((proc.stderr or proc.stdout or "Command failed").strip(), proc.returncode or 1)
    return proc


def load_config() -> dict[str, str]:
    if not CONFIG_FILE.is_file() or CONFIG_FILE.is_symlink():
        raise HelperError(f"Missing DHCP helper configuration: {CONFIG_FILE}")
    meta = CONFIG_FILE.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o022:
        raise HelperError("DHCP helper configuration must be root-owned and not group/world writable")
    data: dict[str, str] = {}
    for raw in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    required = {
        "STAGING_DIR", "DHCP_BACKUP_DIR", "KEA_DHCP4_CONFIG", "KEA_DHCP6_CONFIG",
        "KEA_LEASE_ROOT", "APP_USER",
    }
    missing = required - data.keys()
    if missing:
        raise HelperError("Missing DHCP helper settings: " + ", ".join(sorted(missing)))
    return data


def family_value(raw: str) -> int:
    if raw not in {"4", "6"}:
        raise HelperError("DHCP family must be 4 or 6", 2)
    return int(raw)


def binary(family: int) -> str:
    return f"kea-dhcp{family}"


def service(family: int) -> str:
    return f"kea-dhcp{family}-server"


def config_path(config: dict[str, str], family: int) -> Path:
    return Path(config[f"KEA_DHCP{family}_CONFIG"])


def expected_root(family: int) -> str:
    return f"Dhcp{family}"


def reject_unsafe(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in UNSAFE_KEYS:
                raise HelperError(f"Unsafe Kea key is blocked: {path}.{key}", 2)
            reject_unsafe(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_unsafe(child, f"{path}[{index}]")


def load_json_file(path: Path, family: int) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
        raise HelperError("DHCP configuration must be a regular file up to 8 MiB", 2)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HelperError(f"Invalid DHCP JSON: {exc}", 2) from exc
    root = expected_root(family)
    if not isinstance(value, dict) or set(value) != {root} or not isinstance(value[root], dict):
        raise HelperError(f"Configuration must contain exactly one top-level {root} object", 2)
    reject_unsafe(value)
    return value


def staged_file(config: dict[str, str], raw: str) -> Path:
    root = Path(config["STAGING_DIR"]).resolve(strict=True)
    value = Path(raw)
    if value.is_symlink() or not value.is_file():
        raise HelperError("Staged DHCP configuration must be a regular file", 2)
    parent = value.parent.resolve(strict=True)
    if parent != root:
        raise HelperError("Staged DHCP configuration is outside STAGING_DIR", 2)
    return value.resolve(strict=True)


@contextlib.contextmanager
def trusted_kea_candidate(config: dict[str, str], family: int, source: Path) -> Iterator[Path]:
    """Copy an untrusted staged/backup file into Kea's AppArmor-readable config dir.

    Ubuntu's Kea AppArmor profile intentionally cannot read the application's
    staging directory. The helper validates path/JSON first, then creates a
    root-owned temporary candidate next to the real Kea config. The candidate
    never becomes active by itself and is removed after syntax validation.
    """
    target = config_path(config, family)
    directory = target.parent.resolve(strict=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".chrislab-dhcp{family}-", suffix=".json", dir=directory)
    temp = Path(temp_name)
    try:
        with source.open("rb") as src, os.fdopen(fd, "wb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        os.chown(temp, 0, 0)
        os.chmod(temp, 0o600)
        yield temp
    finally:
        temp.unlink(missing_ok=True)


def validate_kea(family: int, path: Path) -> str:
    proc = run([binary(family), "-t", str(path)], timeout=60)
    return (proc.stdout + proc.stderr).strip() or "Configuration valid"


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_replace(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    old = target.stat() if target.exists() and not target.is_symlink() else None
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temp = Path(temp_name)
    try:
        with source.open("rb") as src, os.fdopen(fd, "wb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        if old:
            os.chown(temp, old.st_uid, old.st_gid)
            os.chmod(temp, stat.S_IMODE(old.st_mode))
        else:
            os.chown(temp, 0, 0)
            os.chmod(temp, 0o644)
        os.replace(temp, target)
        fsync_dir(target.parent)
    finally:
        temp.unlink(missing_ok=True)


def active(service_name: str) -> bool:
    return run(["systemctl", "is-active", "--quiet", service_name], check=False).returncode == 0


def enabled(service_name: str) -> bool:
    return run(["systemctl", "is-enabled", "--quiet", service_name], check=False).returncode == 0


def backup_current(config: dict[str, str], family: int, target: Path) -> Path | None:
    if not target.exists():
        return None
    if target.is_symlink() or not target.is_file():
        raise HelperError("Active Kea configuration is not a regular file", 2)
    backup_root = Path(config["DHCP_BACKUP_DIR"])
    backup_root.mkdir(parents=True, exist_ok=True)
    os.chown(backup_root, 0, 0)
    os.chmod(backup_root, 0o750)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = backup_root / f"kea-dhcp{family}-{stamp}.json"
    counter = 0
    while destination.exists():
        counter += 1
        destination = backup_root / f"kea-dhcp{family}-{stamp[:-1]}-{counter:02d}Z.json"
    shutil.copy2(target, destination)
    os.chown(destination, 0, 0)
    os.chmod(destination, 0o600)
    return destination


def cmd_validate(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    source = staged_file(config, args.file)
    load_json_file(source, family)
    with trusted_kea_candidate(config, family, source) as candidate:
        print(validate_kea(family, candidate))


def cmd_apply(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    source = staged_file(config, args.file)
    load_json_file(source, family)
    with trusted_kea_candidate(config, family, source) as candidate:
        validate_kea(family, candidate)
    target = config_path(config, family)
    was_active = active(service(family))
    backup = backup_current(config, family, target)
    try:
        atomic_replace(source, target)
        validate_kea(family, target)
        if was_active:
            run(["systemctl", "restart", service(family)], timeout=90)
            if not active(service(family)):
                raise HelperError(f"{service(family)} did not become active after restart")
    except Exception as exc:
        if backup is not None:
            atomic_replace(backup, target)
            if was_active:
                run(["systemctl", "restart", service(family)], timeout=90, check=False)
        raise HelperError(f"DHCP apply failed and previous configuration was restored: {exc}") from exc
    print("APPLY_OK" if was_active else "APPLY_OK_SERVICE_STOPPED")


def cmd_read_config(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    target = config_path(config, family)
    if not target.is_file() or target.is_symlink() or target.stat().st_size > 8 * 1024 * 1024:
        raise HelperError("Active Kea configuration is unavailable", 2)
    load_json_file(target, family)
    sys.stdout.write(target.read_text(encoding="utf-8"))


def cmd_status(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    name = service(family)
    version_proc = run([binary(family), "-V"], check=False)
    version = (version_proc.stdout or version_proc.stderr).strip()
    target = config_path(config, family)
    print(json.dumps({
        "family": family,
        "service": name,
        "active": active(name),
        "enabled": enabled(name),
        "version": version,
        "config": str(target),
        "config_exists": target.is_file() and not target.is_symlink(),
    }))


def cmd_service(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    action = args.action
    if action not in {"start", "stop", "restart", "enable", "disable", "enable-start", "disable-stop"}:
        raise HelperError("Unsupported DHCP service action", 2)
    name = service(family)
    target = config_path(config, family)
    if action == "start":
        validate_kea(family, target)
        run(["systemctl", "start", name], timeout=90)
    elif action == "stop":
        run(["systemctl", "stop", name], timeout=90)
    elif action == "restart":
        validate_kea(family, target)
        run(["systemctl", "restart", name], timeout=90)
    elif action == "enable":
        run(["systemctl", "enable", name], timeout=30)
    elif action == "disable":
        run(["systemctl", "disable", name], timeout=30)
    elif action == "enable-start":
        validate_kea(family, target)
        run(["systemctl", "enable", "--now", name], timeout=90)
    else:
        run(["systemctl", "disable", "--now", name], timeout=90)
    print("SERVICE_OK")


def active_lease_path(config: dict[str, str], family: int) -> Path | None:
    target = config_path(config, family)
    if not target.is_file() or target.is_symlink():
        return None
    document = load_json_file(target, family)
    lease = document[expected_root(family)].get("lease-database", {})
    if not isinstance(lease, dict) or lease.get("type", "memfile") != "memfile":
        return None
    fallback = f"/var/lib/kea/kea-leases{family}.csv"
    candidate = Path(str(lease.get("name") or fallback)).resolve(strict=False)
    root = Path(config["KEA_LEASE_ROOT"]).resolve(strict=True)
    if candidate != root and root not in candidate.parents:
        raise HelperError("Configured memfile lease path is outside KEA_LEASE_ROOT", 2)
    return candidate


def cmd_leases(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    limit = max(1, min(int(args.limit), 2000))
    path = active_lease_path(config, family)
    if path is None or not path.is_file() or path.is_symlink():
        print("[]")
        return
    if path.stat().st_size > 128 * 1024 * 1024:
        raise HelperError("Lease file exceeds 128 MiB", 2)
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append({str(key): str(value or "") for key, value in row.items() if key is not None})
            if len(rows) > limit:
                rows.pop(0)
    print(json.dumps(rows))


def cmd_logs(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    lines = max(1, min(int(args.lines), 1000))
    proc = run(["journalctl", "-u", service(family), "-n", str(lines), "--no-pager", "-o", "short-iso"], timeout=30, check=False)
    if proc.returncode not in {0, 1}:
        raise HelperError(proc.stderr.strip() or "journalctl failed", proc.returncode)
    sys.stdout.write(proc.stdout)


def cmd_backups(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    root = Path(config["DHCP_BACKUP_DIR"])
    if not root.is_dir():
        print("[]")
        return
    items = []
    for path in sorted(root.glob(f"kea-dhcp{family}-*.json"), reverse=True)[:100]:
        if path.is_file() and not path.is_symlink() and BACKUP_NAME_RE.fullmatch(path.name):
            items.append({"name": path.name, "size": path.stat().st_size, "mtime": int(path.stat().st_mtime)})
    print(json.dumps(items))


def cmd_restore(args: argparse.Namespace, config: dict[str, str]) -> None:
    family = family_value(args.family)
    match = BACKUP_NAME_RE.fullmatch(args.name)
    if not match or match.group(1) != str(family):
        raise HelperError("Invalid DHCP backup name", 2)
    root = Path(config["DHCP_BACKUP_DIR"]).resolve(strict=True)
    backup = (root / args.name).resolve(strict=True)
    if backup.parent != root or not backup.is_file() or backup.is_symlink():
        raise HelperError("DHCP backup not found", 2)
    load_json_file(backup, family)
    with trusted_kea_candidate(config, family, backup) as candidate:
        validate_kea(family, candidate)
    target = config_path(config, family)
    was_active = active(service(family))
    safety = backup_current(config, family, target)
    try:
        atomic_replace(backup, target)
        validate_kea(family, target)
        if was_active:
            run(["systemctl", "restart", service(family)], timeout=90)
    except Exception as exc:
        if safety is not None:
            atomic_replace(safety, target)
            if was_active:
                run(["systemctl", "restart", service(family)], timeout=90, check=False)
        raise HelperError(f"DHCP restore failed: {exc}") from exc
    print("RESTORE_OK")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Restricted Kea DHCP helper for ChrisLab DNS")
    sub = root.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate"); p.add_argument("--family", required=True); p.add_argument("--file", required=True); p.set_defaults(func=cmd_validate)
    p = sub.add_parser("apply"); p.add_argument("--family", required=True); p.add_argument("--file", required=True); p.add_argument("--file", required=True); p.set_defaults(func=cmd_apply)
    p = sub.add_parser("read-config"); p.add_argument("--family", required=True); p.set_defaults(func=cmd_read_config)
    p = sub.add_parser("status"); p.add_argument("--family", required=True); p.set_defaults(func=cmd_status)
    p = sub.add_parser("service"); p.add_argument("--family", required=True); p.add_argument("--action", required=True); p.set_defaults(func=cmd_service)
    p = sub.add_parser("leases"); p.add_argument("--family", required=True); p.add_argument("--limit", default="250"); p.set_defaults(func=cmd_leases)
    p = sub.add_parser("logs"); p.add_argument("--family", required=True); p.add_argument("--lines", default="100"); p.set_defaults(func=cmd_logs)
    p = sub.add_parser("backups"); p.add_argument("--family", required=True); p.set_defaults(func=cmd_backups)
    p = sub.add_parser("restore"); p.add_argument("--family", required=True); p.add_argument("--name", required=True); p.set_defaults(func=cmd_restore)
    return root


def main() -> int:
    if os.geteuid() != 0:
        print("DHCP helper must run as root", file=sys.stderr)
        return 1
    try:
        config = load_config()
        args = parser().parse_args()
        args.func(args, config)
        return 0
    except HelperError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code if 1 <= exc.code <= 125 else 1
    except Exception as exc:
        print(f"Unexpected DHCP helper error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
