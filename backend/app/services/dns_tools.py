from __future__ import annotations

import time

import dns.exception
import dns.resolver

from ..errors import AppError


def lookup(name: str, record_type: str, server: str | None = None) -> dict[str, object]:
    resolver = dns.resolver.Resolver(configure=server is None)
    if server:
        resolver.nameservers = [server]
    resolver.timeout = 3.0
    resolver.lifetime = 6.0
    started = time.perf_counter()
    try:
        answer = resolver.resolve(name, record_type, raise_on_no_answer=False, search=False)
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        records = [rdata.to_text() for rdata in answer] if answer.rrset is not None else []
        return {
            "name": name,
            "type": record_type,
            "status": "NOERROR",
            "response_time_ms": elapsed,
            "records": records,
            "canonical_name": answer.canonical_name.to_text(),
        }
    except dns.resolver.NXDOMAIN as exc:
        raise AppError("DNS_NXDOMAIN", "DNS name does not exist", 404, str(exc)) from exc
    except dns.resolver.NoNameservers as exc:
        raise AppError("DNS_NO_NAMESERVERS", "No DNS server could answer the query", 502, str(exc)) from exc
    except dns.exception.Timeout as exc:
        raise AppError("DNS_TIMEOUT", "DNS query timed out", 504, str(exc)) from exc
    except dns.exception.DNSException as exc:
        raise AppError("DNS_LOOKUP_FAILED", "DNS lookup failed", 422, str(exc)) from exc
