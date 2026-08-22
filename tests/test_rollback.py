import pytest
from sqlalchemy import func, select

from backend.app.errors import AppError
from backend.app.models import Record, Zone
from backend.app.schemas import RecordCreate, ZoneCreate
from backend.app.services.zones import ZoneService


def test_database_rolls_back_when_apply_fails(db, monkeypatch):
    service = ZoneService(db)
    zone = service.create(ZoneCreate(name="rollback.test"), "tester")
    original_version = zone.version
    original_count = db.scalar(select(func.count(Record.id)).where(Record.zone_id == zone.id))

    def fail_apply(self, current_zone, reason, username):
        raise AppError("BIND_APPLY_FAILED", "forced test failure", 422)

    monkeypatch.setattr(ZoneService, "_apply", fail_apply)
    with pytest.raises(AppError):
        service.add_record(zone, RecordCreate(name="www", type="A", value="192.0.2.9", ttl=3600, zone_version=original_version), "tester")

    db.expire_all()
    fresh = db.scalar(select(Zone).where(Zone.name == "rollback.test"))
    count = db.scalar(select(func.count(Record.id)).where(Record.zone_id == fresh.id))
    assert fresh.version == original_version
    assert count == original_count
