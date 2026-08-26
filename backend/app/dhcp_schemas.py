from __future__ import annotations

import ipaddress
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

DhcpFamily = Literal[4, 6]


class DhcpRawConfig(BaseModel):
    config: dict[str, Any]


class DhcpGlobalUpdate(BaseModel):
    interfaces: list[str] = Field(default_factory=list, max_length=64)
    valid_lifetime: int = Field(default=3600, ge=60, le=31_536_000)
    renew_timer: int = Field(default=900, ge=0, le=31_536_000)
    rebind_timer: int = Field(default=1800, ge=0, le=31_536_000)
    preferred_lifetime: int | None = Field(default=None, ge=60, le=31_536_000)
    authoritative: bool = True
    dns_servers: list[str] = Field(default_factory=list, max_length=16)
    domain_name: str | None = Field(default=None, max_length=253)

    @field_validator("interfaces")
    @classmethod
    def validate_interfaces(cls, value: list[str]) -> list[str]:
        result: list[str] = []
        for raw in value:
            item = raw.strip()
            if not item:
                continue
            if len(item) > 64 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-/*" for ch in item):
                raise ValueError(f"Invalid interface selector: {item}")
            if item not in result:
                result.append(item)
        return result

    @field_validator("dns_servers")
    @classmethod
    def validate_dns_servers(cls, value: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(item.strip())) for item in value if item.strip()]

    @field_validator("domain_name")
    @classmethod
    def validate_domain(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        candidate = value.strip().rstrip(".")
        if len(candidate) > 253 or any(not label or len(label) > 63 for label in candidate.split(".")):
            raise ValueError("Invalid domain name")
        return candidate

    @model_validator(mode="after")
    def validate_timers(self) -> "DhcpGlobalUpdate":
        if self.renew_timer and self.rebind_timer and self.renew_timer > self.rebind_timer:
            raise ValueError("renew_timer must not exceed rebind_timer")
        if self.rebind_timer and self.rebind_timer > self.valid_lifetime:
            raise ValueError("rebind_timer must not exceed valid_lifetime")
        if self.preferred_lifetime is not None and self.preferred_lifetime > self.valid_lifetime:
            raise ValueError("preferred_lifetime must not exceed valid_lifetime")
        return self


class DhcpSubnetCreate(BaseModel):
    subnet: str
    interface: str | None = Field(default=None, max_length=64)
    pool: str | None = Field(default=None, max_length=200)
    routers: list[str] = Field(default_factory=list, max_length=16)
    dns_servers: list[str] = Field(default_factory=list, max_length=16)
    domain_name: str | None = Field(default=None, max_length=253)
    valid_lifetime: int | None = Field(default=None, ge=60, le=31_536_000)


class DhcpPoolCreate(BaseModel):
    pool: str = Field(min_length=3, max_length=200)


class DhcpReservationCreate(BaseModel):
    identifier_type: Literal["hw-address", "client-id", "duid", "flex-id"]
    identifier: str = Field(min_length=1, max_length=512)
    address: str
    hostname: str | None = Field(default=None, max_length=253)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return str(ipaddress.ip_address(value.strip()))

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        result = value.strip().rstrip(".")
        if len(result) > 253:
            raise ValueError("Hostname is too long")
        return result


class DhcpOptionCreate(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    code: int | None = Field(default=None, ge=0, le=65535)
    data: str = Field(max_length=4096)
    space: str | None = Field(default=None, max_length=128)
    csv_format: bool = True

    @model_validator(mode="after")
    def require_name_or_code(self) -> "DhcpOptionCreate":
        if not self.name and self.code is None:
            raise ValueError("Option name or code is required")
        return self


class DhcpServiceAction(BaseModel):
    action: Literal["start", "stop", "restart", "enable", "disable", "enable-start", "disable-stop"]
