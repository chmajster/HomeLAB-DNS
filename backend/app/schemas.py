from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RecordType = Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "CAA"]


def normalize_zone_name(value: str) -> str:
    text = value.strip().rstrip(".").lower()
    if not text or len(text) > 253:
        raise ValueError("Invalid DNS zone name")
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
    labels = text.split(".")
    if len(labels) < 2 or any(not label_re.fullmatch(label) for label in labels):
        raise ValueError("Invalid DNS zone name")
    try:
        name = dns.name.from_text(text + ".")
    except Exception as exc:
        raise ValueError("Invalid DNS zone name") from exc
    if not name.is_absolute():
        raise ValueError("Zone must be a fully qualified DNS name")
    return text


def normalize_owner(value: str) -> str:
    text = value.strip()
    if text == "@":
        return text
    if not text or len(text) > 253 or any(char in text for char in "\r\n\x00"):
        raise ValueError("Invalid record name")
    if text.endswith("."):
        raise ValueError("Record owner must be relative to the zone or @")
    try:
        dns.name.from_text(text)
    except Exception as exc:
        raise ValueError("Invalid record name") from exc
    return text.lower()


class ZoneCreate(BaseModel):
    name: str
    zone_type: Literal["primary"] = "primary"
    reverse: bool = False
    enabled: bool = True
    default_ttl: Annotated[int, Field(ge=30, le=604800)] = 3600
    soa_mname: str | None = None
    soa_rname: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return normalize_zone_name(value)

    @field_validator("soa_mname", "soa_rname")
    @classmethod
    def validate_soa_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip().lower()
        if any(char in text for char in "\r\n\x00") or not text.endswith("."):
            raise ValueError("SOA names must be absolute DNS names ending with a dot")
        dns.name.from_text(text)
        return text


class ZoneUpdate(BaseModel):
    version: Annotated[int, Field(ge=1)]
    enabled: bool | None = None
    default_ttl: Annotated[int | None, Field(ge=30, le=604800)] = None
    soa_mname: str | None = None
    soa_rname: str | None = None

    @field_validator("soa_mname", "soa_rname")
    @classmethod
    def validate_soa_name(cls, value: str | None) -> str | None:
        return ZoneCreate.validate_soa_name(value)


class ZoneOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    zone_type: str
    reverse: bool
    enabled: bool
    managed: bool
    file_name: str
    default_ttl: int
    serial: int
    version: int
    validation_status: str
    last_modified: datetime
    record_count: int = 0


class RecordCreate(BaseModel):
    name: str = "@"
    type: RecordType
    value: str
    ttl: Annotated[int, Field(ge=30, le=604800)] = 3600
    priority: Annotated[int | None, Field(ge=0, le=65535)] = None
    weight: Annotated[int | None, Field(ge=0, le=65535)] = None
    port: Annotated[int | None, Field(ge=0, le=65535)] = None
    zone_version: Annotated[int, Field(ge=1)]

    @field_validator("name")
    @classmethod
    def validate_owner(cls, value: str) -> str:
        return normalize_owner(value)

    @model_validator(mode="after")
    def validate_rdata(self) -> RecordCreate:
        rtype = self.type
        value = self.value.strip()
        if any(char in value for char in "\r\n\x00"):
            raise ValueError("DNS values cannot contain control characters")
        if rtype == "A":
            ipaddress.IPv4Address(value)
        elif rtype == "AAAA":
            ipaddress.IPv6Address(value)
        elif rtype in {"CNAME", "NS", "PTR"}:
            if not value.endswith("."):
                raise ValueError(f"{rtype} target must end with a dot")
            dns.name.from_text(value)
        elif rtype == "MX":
            if self.priority is None:
                raise ValueError("MX requires priority")
            if not value.endswith("."):
                raise ValueError("MX target must end with a dot")
            dns.name.from_text(value)
        elif rtype == "SRV":
            if self.priority is None or self.weight is None or self.port is None:
                raise ValueError("SRV requires priority, weight and port")
            if not value.endswith("."):
                raise ValueError("SRV target must end with a dot")
            dns.name.from_text(value)
        elif rtype == "CAA":
            parts = value.split(" ", 2)
            if len(parts) != 3:
                raise ValueError('CAA value must be: flags tag "value"')
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CAA, value)
        elif rtype == "TXT":
            candidate = value if value.startswith('"') else f'"{value}"'
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, candidate)
        self.value = value
        return self


RecordUpdate = RecordCreate


class RecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    zone_id: int
    name: str
    type: str
    value: str
    ttl: int
    priority: int | None
    weight: int | None
    port: int | None
    updated_at: datetime


class BulkRecordRequest(BaseModel):
    record_ids: list[int] = Field(min_length=1, max_length=500)
    operation: Literal["delete", "ttl", "export"]
    ttl: Annotated[int | None, Field(ge=30, le=604800)] = None
    zone_version: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def validate_operation(self) -> BulkRecordRequest:
        if self.operation == "ttl" and self.ttl is None:
            raise ValueError("TTL is required for ttl operation")
        return self


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    permissions: list[str] = Field(min_length=1)
    expires_at: datetime | None = None


class TokenCreated(BaseModel):
    id: int
    name: str
    token: str
    permissions: list[str]
    expires_at: datetime | None


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,80}$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["administrator", "operator", "read_only"]


class UserUpdate(BaseModel):
    role: Literal["administrator", "operator", "read_only"] | None = None
    enabled: bool | None = None


class PasswordChange(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class BackupCreate(BaseModel):
    reason: str = Field(default="manual", min_length=1, max_length=255)


class LookupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    type: Literal["A", "AAAA", "MX", "TXT", "NS", "PTR", "CNAME", "SOA", "SRV", "CAA", "ANY"] = "A"
    server: str | None = None

    @field_validator("server")
    @classmethod
    def validate_server(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        ipaddress.ip_address(value)
        return value


class ReverseZoneRequest(BaseModel):
    network: str

    @field_validator("network")
    @classmethod
    def validate_network(cls, value: str) -> str:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4 or network.prefixlen % 8 != 0:
            raise ValueError("Reverse wizard supports IPv4 octet-aligned networks such as /8, /16 or /24")
        return str(network)
