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
RoleType = Literal["administrator", "operator", "read_only"]
TsigAlgorithm = Literal["hmac-sha256", "hmac-sha384", "hmac-sha512"]


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


def normalize_ip_list(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        normalized.append(str(ipaddress.ip_address(text)))
    if len(normalized) != len(set(normalized)):
        raise ValueError("Duplicate DNS server address")
    if len(normalized) > 32:
        raise ValueError("Too many DNS server addresses")
    return normalized


def normalize_tsig_name(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    text = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", text):
        raise ValueError("Invalid TSIG key name")
    return text


class ZoneCreate(BaseModel):
    name: str
    zone_type: Literal["primary", "secondary"] = "primary"
    reverse: bool = False
    enabled: bool = True
    default_ttl: Annotated[int, Field(ge=30, le=604800)] = 3600
    soa_mname: str | None = None
    soa_rname: str | None = None
    primary_servers: list[str] = Field(default_factory=list)
    allow_transfer: list[str] = Field(default_factory=list)
    also_notify: list[str] = Field(default_factory=list)
    tsig_key_name: str | None = None

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

    @field_validator("primary_servers", "allow_transfer", "also_notify")
    @classmethod
    def validate_server_lists(cls, value: list[str]) -> list[str]:
        return normalize_ip_list(value)

    @field_validator("tsig_key_name")
    @classmethod
    def validate_tsig_key_name(cls, value: str | None) -> str | None:
        return normalize_tsig_name(value)

    @model_validator(mode="after")
    def validate_zone_mode(self) -> ZoneCreate:
        if self.zone_type == "secondary" and not self.primary_servers:
            raise ValueError("Secondary zones require at least one primary server")
        if self.zone_type == "secondary" and (self.allow_transfer or self.also_notify):
            raise ValueError("allow_transfer and also_notify apply only to primary zones")
        if self.zone_type == "primary" and self.primary_servers:
            raise ValueError("primary_servers applies only to secondary zones")
        return self


class ZoneUpdate(BaseModel):
    version: Annotated[int, Field(ge=1)]
    enabled: bool | None = None
    default_ttl: Annotated[int | None, Field(ge=30, le=604800)] = None
    soa_mname: str | None = None
    soa_rname: str | None = None
    primary_servers: list[str] | None = None
    allow_transfer: list[str] | None = None
    also_notify: list[str] | None = None
    tsig_key_name: str | None = None

    @field_validator("soa_mname", "soa_rname")
    @classmethod
    def validate_soa_name(cls, value: str | None) -> str | None:
        return ZoneCreate.validate_soa_name(value)

    @field_validator("primary_servers", "allow_transfer", "also_notify")
    @classmethod
    def validate_server_lists(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else normalize_ip_list(value)

    @field_validator("tsig_key_name")
    @classmethod
    def validate_tsig_key_name(cls, value: str | None) -> str | None:
        return normalize_tsig_name(value)


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
    primary_servers: list[str] = Field(default_factory=list)
    allow_transfer: list[str] = Field(default_factory=list)
    also_notify: list[str] = Field(default_factory=list)
    tsig_key_name: str | None = None
    last_modified: datetime
    record_count: int = 0


class ZoneRevisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    zone_name: str
    version: int
    serial: int
    reason: str
    created_by: str
    created_at: datetime


class ZoneRestoreRequest(BaseModel):
    version: Annotated[int, Field(ge=1)]


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
    role: RoleType


class UserUpdate(BaseModel):
    role: RoleType | None = None
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


class DnsServerCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,120}$")
    address: str
    role: Literal["primary", "secondary"] = "secondary"
    enabled: bool = True
    tsig_key_name: str | None = None
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return str(ipaddress.ip_address(value.strip()))

    @field_validator("tsig_key_name")
    @classmethod
    def validate_tsig(cls, value: str | None) -> str | None:
        return normalize_tsig_name(value)


class DnsServerUpdate(BaseModel):
    name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,120}$")
    address: str | None = None
    role: Literal["primary", "secondary"] | None = None
    enabled: bool | None = None
    tsig_key_name: str | None = None
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str | None) -> str | None:
        return None if value is None else str(ipaddress.ip_address(value.strip()))

    @field_validator("tsig_key_name")
    @classmethod
    def validate_tsig(cls, value: str | None) -> str | None:
        return normalize_tsig_name(value)


class DnsServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    address: str
    role: str
    enabled: bool
    tsig_key_name: str | None
    notes: str | None
    last_check_at: datetime | None
    last_check_status: str | None
    created_at: datetime


class TsigKeyCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,120}$")
    algorithm: TsigAlgorithm = "hmac-sha256"
    secret: str | None = Field(default=None, min_length=16, max_length=512)


class TsigKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    algorithm: str
    created_at: datetime


class TsigKeyCreated(TsigKeyOut):
    secret: str
