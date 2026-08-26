from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from ..errors import AppError
from .dhcp import DhcpService, _family_root


class DhcpRuntimeOps:
    """Runtime-only Kea operations kept separate from draft manipulation."""

    def __init__(self, service: DhcpService) -> None:
        self.service = service

    def interfaces(self) -> list[str]:
        """Enumerate interfaces without requiring AF_NETLINK in the web sandbox."""
        names: set[str] = set()
        sysfs = Path("/sys/class/net")
        try:
            names = {entry.name for entry in sysfs.iterdir() if entry.name != "lo"}
        except OSError:
            try:
                names = {name for _, name in socket.if_nameindex() if name != "lo"}
            except OSError:
                names = set()
        return sorted(name for name in names if name and "/" not in name and "\x00" not in name)

    def backups(self, family: int) -> list[dict[str, Any]]:
        _family_root(family)
        raw = self.service._run_helper("backups", "--family", str(family), timeout=30)
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AppError("DHCP_BACKUPS_INVALID", "DHCP helper returned invalid backup data", 500, str(exc)) from exc
        if not isinstance(result, list):
            raise AppError("DHCP_BACKUPS_INVALID", "DHCP helper returned invalid backup data", 500)
        return [item for item in result if isinstance(item, dict)]

    def restore(self, family: int, name: str) -> str:
        _family_root(family)
        if not name or "/" in name or "\\" in name or "\x00" in name:
            raise AppError("INVALID_DHCP_BACKUP", "Invalid DHCP backup name", 422)
        return self.service._run_helper("restore", "--family", str(family), "--name", name, timeout=90).strip()
