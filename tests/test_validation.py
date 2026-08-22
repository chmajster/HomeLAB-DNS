import pytest
from pydantic import ValidationError

from backend.app.errors import AppError
from backend.app.schemas import RecordCreate, ZoneCreate
from backend.app.services.zonefile import parse_zone_text


def test_invalid_zone_name_rejected():
    with pytest.raises(ValidationError):
        ZoneCreate(name="bad zone")


def test_invalid_ipv4_rejected():
    with pytest.raises(ValidationError):
        RecordCreate(name="www", type="A", value="999.1.2.3", ttl=3600, zone_version=1)


def test_invalid_ipv6_rejected():
    with pytest.raises(ValidationError):
        RecordCreate(name="www", type="AAAA", value="not-v6", ttl=3600, zone_version=1)


def test_cname_requires_absolute_target():
    with pytest.raises(ValidationError):
        RecordCreate(name="www", type="CNAME", value="target.example.com", ttl=3600, zone_version=1)


def test_mx_requires_priority():
    with pytest.raises(ValidationError):
        RecordCreate(name="@", type="MX", value="mail.example.com.", ttl=3600, zone_version=1)


def test_invalid_zone_file_rejected():
    with pytest.raises(AppError):
        parse_zone_text("example.com", "$ORIGIN example.com.\nwww IN A 192.0.2.1\n")
