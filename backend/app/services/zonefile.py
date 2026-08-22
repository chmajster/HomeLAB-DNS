from __future__ import annotations

import hashlib
import shlex
from dataclasses import dataclass
from pathlib import Path

import dns.exception
import dns.name
import dns.rdatatype
import dns.zone

from ..errors import AppError


@dataclass(frozen=True)
class ParsedRecord:
    name: str
    type: str
    value: str
    ttl: int
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


@dataclass(frozen=True)
class ParsedZone:
    name: str
    default_ttl: int
    soa_mname: str
    soa_rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    records: tuple[ParsedRecord, ...]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(131072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_owner(owner: dns.name.Name, origin: dns.name.Name) -> str:
    if owner == origin:
        return "@"
    try:
        return owner.relativize(origin).to_text()
    except dns.name.NoParent:
        return owner.to_text()


def parse_zone_text(zone_name: str, text: str) -> ParsedZone:
    origin = dns.name.from_text(zone_name.rstrip(".") + ".")
    try:
        zone = dns.zone.from_text(text, origin=origin, relativize=False, check_origin=True)
    except (dns.exception.DNSException, ValueError) as exc:
        raise AppError("ZONE_PARSE_FAILED", "Zone file could not be parsed", 422, str(exc)) from exc
    soa = zone.get_rdataset(origin, "SOA")
    if soa is None or len(soa) != 1:
        raise AppError("ZONE_SOA_INVALID", "Zone must contain exactly one SOA record", 422)
    soa_rdata = next(iter(soa))
    records: list[ParsedRecord] = []
    default_ttl = int(soa.ttl or 3600)
    for owner, node in zone.nodes.items():
        absolute = owner if owner.is_absolute() else owner.derelativize(origin)
        owner_text = _relative_owner(absolute, origin)
        for rdataset in node.rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            if rtype == "SOA":
                continue
            if rtype not in {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "CAA"}:
                continue
            for rdata in rdataset:
                priority = weight = port = None
                if rtype == "MX":
                    priority = int(rdata.preference)
                    value = rdata.exchange.to_text()
                elif rtype == "SRV":
                    priority = int(rdata.priority)
                    weight = int(rdata.weight)
                    port = int(rdata.port)
                    value = rdata.target.to_text()
                else:
                    value = rdata.to_text()
                records.append(ParsedRecord(owner_text, rtype, value, int(rdataset.ttl), priority, weight, port))
    return ParsedZone(
        name=zone_name.rstrip(".").lower(),
        default_ttl=default_ttl,
        soa_mname=soa_rdata.mname.to_text(),
        soa_rname=soa_rdata.rname.to_text(),
        serial=int(soa_rdata.serial),
        refresh=int(soa_rdata.refresh),
        retry=int(soa_rdata.retry),
        expire=int(soa_rdata.expire),
        minimum=int(soa_rdata.minimum),
        records=tuple(records),
    )


def format_rdata(record_type: str, value: str, priority: int | None, weight: int | None, port: int | None) -> str:
    if record_type == "MX":
        if priority is None:
            raise AppError("INVALID_RECORD", "MX requires priority", 422)
        return f"{priority} {value}"
    if record_type == "SRV":
        if priority is None or weight is None or port is None:
            raise AppError("INVALID_RECORD", "SRV requires priority, weight and port", 422)
        return f"{priority} {weight} {port} {value}"
    if record_type == "TXT":
        return value if value.startswith('"') else f'"{value.replace(chr(34), chr(92) + chr(34))}"'
    return value


def render_zone(zone) -> str:
    origin = zone.name.rstrip(".") + "."
    lines = [
        f"$ORIGIN {origin}",
        f"$TTL {zone.default_ttl}",
        "@ IN SOA " + f"{zone.soa_mname} {zone.soa_rname} (",
        f"    {zone.serial} ; serial",
        f"    {zone.refresh} ; refresh",
        f"    {zone.retry} ; retry",
        f"    {zone.expire} ; expire",
        f"    {zone.minimum} ; minimum",
        ")",
        "",
    ]
    for record in sorted(zone.records, key=lambda item: (item.name, item.type, item.id or 0)):
        rdata = format_rdata(record.type, record.value, record.priority, record.weight, record.port)
        lines.append(f"{record.name}\t{record.ttl}\tIN\t{record.type}\t{rdata}")
    return "\n".join(lines).rstrip() + "\n"


def safe_zone_filename(zone_name: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789.-"
    lowered = zone_name.lower().rstrip(".")
    if not lowered or any(char not in allowed for char in lowered) or ".." in lowered:
        raise AppError("INVALID_ZONE_NAME", "Unsafe zone name", 422)
    return f"db.{lowered}"
