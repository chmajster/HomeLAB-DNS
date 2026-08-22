from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AppError(Exception):
    code: str
    message: str
    status_code: int = 400
    details: str | None = None

    def __str__(self) -> str:
        return self.message
