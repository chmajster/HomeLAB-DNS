from __future__ import annotations

from datetime import datetime, timezone


def next_soa_serial(current: int, now: datetime | None = None) -> int:
    moment = now or datetime.now(timezone.utc)
    base = int(moment.strftime("%Y%m%d")) * 100
    if current < base:
        return base + 1
    return current + 1
