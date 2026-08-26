from __future__ import annotations

import os
import tempfile
from pathlib import Path

import dns.dnssec
import dns.name
import dns.resolver
from sqlalchemy.orm import Session

from ..errors import AppError
from ..models import Zone
from .zonefile import render_zone
from .zones import ZoneService, zone_lock

DNSSEC_POLICIES = {"none", "default", "insecure"}
DNSSEC_RUNTIME_DIR = Path(os.getenv("BIND_DNSSEC_DIR", "/var/cache/bind/chrislab-dnssec"))


def _install_zone_stanza_patch() -> None:
    """Teach ZoneService to point signed primary zones at a writable runtime copy.

    Canonical unsigned zone files stay under /etc/bind/zones and remain managed
    transactionally by the privileged helper. BIND's inline signer uses a copy
    under /var/cache/bind, where it may safely create .signed/.jnl/.jbk files.
    """

    if getattr(ZoneService, "_dnssec_stanza_installed", False):
        return

    original = ZoneService._zone_stanza

    def dnssec_zone_stanza(self: ZoneService, zone: Zone) -> list[str]:
        lines = original(self, zone)
        policy = getattr(zone, "dnssec_policy", "none") or "none"
        if policy == "none":
            return lines
        if policy not in DNSSEC_POLICIES:
            raise AppError("INVALID_DNSSEC_POLICY", "Stored DNSSEC policy is invalid", 500)
        if zone.zone_type != "primary":
            raise AppError("DNSSEC_PRIMARY_ONLY", "DNSSEC signing can only be managed on primary zones", 422)

        runtime_path = DNSSEC_RUNTIME_DIR / zone.file_name
        for index, line in enumerate(lines):
            if line.strip().startswith("file "):
                lines[index] = f'    file "{runtime_path}";'
                lines.insert(index + 1, f"    dnssec-policy {policy};")
                lines.insert(index + 2, "    inline-signing yes;")
                break
        else:
            raise AppError("DNSSEC_ZONE_FILE_MISSING", "Primary zone stanza has no file directive", 500)
        return lines

    ZoneService._zone_stanza = dnssec_zone_stanza  # type: ignore[method-assign]
    ZoneService._dnssec_stanza_installed = True  # type: ignore[attr-defined]


_install_zone_stanza_patch()


class DnssecService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.zones = ZoneService(db)

    def _runtime_path(self, zone: Zone) -> Path:
        path = DNSSEC_RUNTIME_DIR / zone.file_name
        if path.parent != DNSSEC_RUNTIME_DIR or "/" in zone.file_name or "\\" in zone.file_name:
            raise AppError("INVALID_DNSSEC_PATH", "Invalid DNSSEC runtime filename", 500)
        return path

    def _snapshot_runtime(self, path: Path) -> tuple[bool, bytes | None]:
        if not path.exists():
            return False, None
        if path.is_symlink() or not path.is_file():
            raise AppError("INVALID_DNSSEC_RUNTIME", "DNSSEC runtime path must be a regular file", 500)
        if path.stat().st_size > 8 * 1024 * 1024:
            raise AppError("DNSSEC_RUNTIME_TOO_LARGE", "DNSSEC runtime zone exceeds 8 MiB", 500)
        return True, path.read_bytes()

    def _write_runtime(self, path: Path, content: str) -> None:
        root = DNSSEC_RUNTIME_DIR
        if not root.is_dir() or root.is_symlink():
            raise AppError(
                "DNSSEC_RUNTIME_UNAVAILABLE",
                "DNSSEC runtime directory is unavailable",
                500,
                f"Expected a real directory at {root}",
            )
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o640)
            os.replace(temp_name, path)
            directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            Path(temp_name).unlink(missing_ok=True)

    def _restore_runtime(self, path: Path, existed: bool, content: bytes | None) -> None:
        if not existed:
            path.unlink(missing_ok=True)
            return
        if content is None:
            return
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.rollback.", dir=DNSSEC_RUNTIME_DIR)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o640)
            os.replace(temp_name, path)
        finally:
            Path(temp_name).unlink(missing_ok=True)

    def set_policy(self, zone: Zone, policy: str, version: int, username: str) -> Zone:
        normalized = policy.strip().lower()
        if normalized not in DNSSEC_POLICIES:
            raise AppError("INVALID_DNSSEC_POLICY", "DNSSEC policy must be none, default or insecure", 422)
        if not zone.managed:
            raise AppError("EXTERNAL_ZONE_READ_ONLY", "Externally managed zones are read-only", 409)
        if zone.zone_type != "primary" and normalized != "none":
            raise AppError("DNSSEC_PRIMARY_ONLY", "DNSSEC signing can only be managed on primary zones", 422)

        with zone_lock(zone.name):
            self.zones._check_external_change(zone)
            if zone.version != version:
                raise AppError("ZONE_VERSION_CONFLICT", "Zone was modified by another administrator", 409)
            if (zone.dnssec_policy or "none") == normalized:
                return zone

            runtime_path = self._runtime_path(zone)
            runtime_existed, runtime_content = self._snapshot_runtime(runtime_path)
            old_policy = zone.dnssec_policy or "none"
            old_version = zone.version
            zone.dnssec_policy = normalized
            zone.version += 1

            try:
                if normalized != "none":
                    self._write_runtime(runtime_path, render_zone(zone))
                self.zones._apply(zone, f"before DNSSEC_POLICY {zone.name} {old_policy}->{normalized}", username)
                self.db.commit()
            except Exception:
                self.db.rollback()
                self._restore_runtime(runtime_path, runtime_existed, runtime_content)
                zone.dnssec_policy = old_policy
                zone.version = old_version
                raise

            self.db.refresh(zone)
            return zone

    def status(self, zone: Zone) -> dict[str, object]:
        policy = zone.dnssec_policy or "none"
        result: dict[str, object] = {
            "zone": zone.name,
            "configured": policy != "none",
            "policy": policy,
            "runtime_ready": self._runtime_path(zone).is_file() if policy != "none" else False,
            "signed": False,
            "dnskey_count": 0,
            "ds_sha256": [],
            "error": None,
        }
        if policy == "none" or not zone.enabled:
            return result

        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["127.0.0.1"]
            resolver.timeout = 2.0
            resolver.lifetime = 3.0
            answer = resolver.resolve(zone.name + ".", "DNSKEY", search=False)
            keys = list(answer)
            ds_records: list[str] = []
            owner = dns.name.from_text(zone.name + ".")
            for key in keys:
                if int(getattr(key, "flags", 0)) & 1:
                    ds_records.append(dns.dnssec.make_ds(owner, key, "SHA256").to_text())
            result.update(
                {
                    "signed": bool(keys),
                    "dnskey_count": len(keys),
                    "ds_sha256": ds_records,
                }
            )
        except Exception as exc:
            result["error"] = str(exc)
        return result
