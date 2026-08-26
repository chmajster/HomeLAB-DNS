# DNS HA and replication monitoring

ChrisLab DNS 0.6.0 adds live replication diagnostics for authoritative BIND servers registered in **DNS Platform**.

## What the HA panel checks

For every enabled zone the panel calculates an expected SOA serial and compares it with the local BIND instance and registered DNS servers.

- Primary zones use the serial stored by ChrisLab DNS as the expected serial.
- Secondary zones query all configured `primary_servers` and select the newest serial using RFC 1982 32-bit serial arithmetic.
- Local BIND is queried on `127.0.0.1`.
- Enabled servers registered in **DNS Platform** are queried using their configured address.
- When a TSIG key is assigned to a server or zone, the SOA/transfer diagnostic query uses that key.

States are reported as:

- `in_sync` — serial equals the expected serial;
- `lagging` — server is behind, including the calculated serial distance;
- `ahead` — server advertises a newer serial;
- `serial_unknown` — a serial was returned but no expected serial could be established;
- `unreachable`, `query_error`, `not_authoritative` or `soa_missing` — the probe could not establish a healthy authoritative SOA state.

The last probe result is persisted per DNS server and zone, including serial, lag, authoritative flag, latency and the last time the server was confirmed in sync.

## AXFR and IXFR diagnostics

The HA panel exposes explicit **AXFR** and **IXFR** test buttons for each registered server/zone pair. The test is a bounded TCP transfer handshake and records:

- test type;
- success/refused/failed state;
- DNS response code;
- response RRset count;
- latency;
- last successful transfer time.

The test uses the server TSIG key first, falling back to the zone TSIG key.

These actions are diagnostics only. They do not automatically alter transfer policy, promote a server, modify a zone or restart BIND.

## REST API

The relevant endpoints are:

- `GET /api/v1/ha/replication` — replication overview for all enabled zones;
- `GET /api/v1/zones/{zone_name}/replication` — replication state for one zone;
- `POST /api/v1/servers/{server_id}/zones/{zone_name}/transfer-test?transfer_type=AXFR`;
- `POST /api/v1/servers/{server_id}/zones/{zone_name}/transfer-test?transfer_type=IXFR`.

Read-only replication checks require `zones.read`. Transfer tests require `settings.manage` and CSRF protection for session-authenticated requests.

## Serial wrap-around

SOA serial comparison follows RFC 1982-style 32-bit arithmetic. This prevents false lag/ahead results when a serial wraps from `4294967295` to `0`.

## Operational use

For a primary/secondary deployment:

1. register all authoritative servers in **DNS Platform**;
2. configure `allow-transfer` and `also-notify` on primary zones;
3. configure `primary_servers` on secondary zones;
4. assign TSIG keys where transfer authentication is required;
5. open the **Stan replikacji DNS** panel and verify that all intended authoritative nodes report `in_sync`;
6. use AXFR/IXFR diagnostics when replication is delayed or refused.

The HA panel is intentionally observational. Automatic failover, primary election and multi-writer DNS are not performed by this module.