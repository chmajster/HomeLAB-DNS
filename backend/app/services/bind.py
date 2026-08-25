from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings, get_settings
from ..errors import AppError


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class BindService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def _run_helper(self, *args: str, timeout: int = 30) -> CommandResult:
        command = [*self.settings.bind_helper, *args]
        if not command:
            raise AppError("HELPER_NOT_CONFIGURED", "Privileged BIND helper is not configured", 500)
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=False, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AppError("BIND_HELPER_FAILED", "Unable to execute BIND helper", 500, str(exc)) from exc
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def _require_ok(self, result: CommandResult, code: str, message: str) -> CommandResult:
        if result.returncode != 0:
            raise AppError(code, message, 422, result.stderr or result.stdout)
        return result

    def validate_zone(self, zone: str, staged_file: Path) -> str:
        result = self._run_helper("validate-zone", "--zone", zone, "--file", str(staged_file))
        return self._require_ok(result, "ZONE_VALIDATION_FAILED", "Zone validation failed").stdout

    def validate_config(self) -> str:
        result = self._run_helper("validate-config")
        return self._require_ok(result, "CONFIG_VALIDATION_FAILED", "BIND configuration validation failed").stdout

    def validate_candidate(self, zone: str, staged_zone: Path | None, target: str, staged_managed: Path, remove: bool = False) -> str:
        args = ["validate-candidate", "--zone", zone, "--target", target, "--staged-managed", str(staged_managed)]
        if staged_zone is not None:
            args.extend(["--staged-zone", str(staged_zone)])
        if remove:
            args.append("--remove")
        result = self._run_helper(*args, timeout=60)
        return self._require_ok(result, "CONFIG_VALIDATION_FAILED", "Candidate BIND configuration validation failed").stdout

    def apply_zone(self, zone: str, staged_zone: Path, target: str, staged_managed: Path) -> None:
        result = self._run_helper(
            "apply-zone", "--zone", zone, "--staged-zone", str(staged_zone),
            "--target", target, "--staged-managed", str(staged_managed), timeout=60,
        )
        self._require_ok(result, "BIND_APPLY_FAILED", "BIND transaction failed")

    def apply_managed_config(self, staged_managed: Path) -> None:
        result = self._run_helper("apply-managed-config", "--staged-managed", str(staged_managed), timeout=60)
        self._require_ok(result, "BIND_APPLY_FAILED", "BIND managed configuration transaction failed")

    def remove_zone(self, zone: str, target: str, staged_managed: Path) -> None:
        result = self._run_helper(
            "remove-zone", "--zone", zone, "--target", target,
            "--staged-managed", str(staged_managed), timeout=60,
        )
        self._require_ok(result, "BIND_REMOVE_FAILED", "BIND zone removal failed")

    def reload(self) -> None:
        self._require_ok(self._run_helper("reload", timeout=45), "BIND_RELOAD_FAILED", "BIND reload failed")

    def retransfer(self, zone: str) -> None:
        self._require_ok(self._run_helper("retransfer", "--zone", zone, timeout=45), "BIND_RETRANSFER_FAILED", "Secondary zone retransfer failed")

    def restart(self) -> None:
        self._require_ok(self._run_helper("restart", timeout=60), "BIND_RESTART_FAILED", "BIND restart failed")

    def status(self) -> dict[str, object]:
        result = self._run_helper("status")
        self._require_ok(result, "BIND_STATUS_FAILED", "Unable to read BIND status")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise AppError("BIND_STATUS_INVALID", "BIND helper returned invalid status", 500, str(exc)) from exc

    def logs(self, lines: int = 200, since_minutes: int = 60, level: str = "info") -> str:
        result = self._run_helper("logs", "--lines", str(lines), "--since-minutes", str(since_minutes), "--level", level)
        return self._require_ok(result, "BIND_LOGS_FAILED", "Unable to read BIND logs").stdout

    def export_bind(self, destination: Path) -> None:
        result = self._run_helper("export-bind", "--dest", str(destination), timeout=60)
        self._require_ok(result, "BACKUP_EXPORT_FAILED", "Unable to backup BIND configuration")

    def restore_bind(self, source: Path) -> None:
        result = self._run_helper("restore-bind", "--source", str(source), timeout=90)
        self._require_ok(result, "RESTORE_FAILED", "Unable to restore BIND configuration")

    def discover_zones(self) -> list[dict[str, str]]:
        result = self._run_helper("discover-zones")
        self._require_ok(result, "DISCOVERY_FAILED", "Unable to discover BIND zones")
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise AppError("DISCOVERY_INVALID", "BIND discovery output is invalid", 500, str(exc)) from exc
        return [item for item in data if isinstance(item, dict)]

    def read_zone(self, path: str) -> str:
        result = self._run_helper("read-zone", "--file", path)
        return self._require_ok(result, "ZONE_READ_FAILED", "Unable to read zone file").stdout
