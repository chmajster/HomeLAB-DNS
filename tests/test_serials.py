from datetime import datetime, timezone

from backend.app.services.serials import next_soa_serial


def test_serial_uses_yyyymmddnn():
    now = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
    assert next_soa_serial(0, now) == 2026082201
    assert next_soa_serial(2026082201, now) == 2026082202


def test_serial_never_moves_backwards():
    now = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
    assert next_soa_serial(2099010199, now) == 2099010200
