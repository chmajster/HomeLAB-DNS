# DNSSEC management

ChrisLab DNS uses BIND's native `dnssec-policy` KASP support instead of invoking `dnssec-signzone` manually.

## Policies

- `none` — no DNSSEC policy is configured for the zone.
- `default` — BIND automatically signs the primary zone and maintains signing keys according to its built-in default KASP.
- `insecure` — BIND performs the controlled transition from a signed zone back to unsigned DNS. Remove the parent DS record as part of this transition before finally selecting `none`.

DNSSEC signing is managed only for panel-managed primary zones. Secondary zones receive already signed data from their primary and therefore cannot enable signing through this panel.

## Storage model

The authoritative unsigned source remains under `/etc/bind/zones` and continues to use the existing ChrisLab DNS transactional write/validate/rollback path.

For a DNSSEC-enabled zone, the generated BIND stanza points to a synchronized runtime copy under:

```text
/var/cache/bind/chrislab-dnssec/
```

The systemd service creates that directory with the application user as owner, the `bind` group as group owner and setgid permissions. This gives `named` a writable location for inline-signing state without making the canonical `/etc/bind/zones` directory writable by BIND.

Every later panel edit of a DNSSEC-enabled zone refreshes the runtime unsigned copy before BIND reloads. If the BIND transaction fails, the previous runtime copy is restored.

## REST API

Read current DNSSEC state and DS records derived from the local DNSKEY RRset:

```text
GET /api/v1/zones/{zone}/dnssec
```

Change the policy using the current optimistic-lock zone version:

```text
PUT /api/v1/zones/{zone}/dnssec
{
  "version": 4,
  "policy": "default"
}
```

The status response contains:

- selected policy;
- whether the runtime zone exists;
- whether DNSKEY records are currently served;
- DNSKEY count;
- SHA-256 DS records suitable for parent/registrar publication;
- an error field when the local DNSKEY query fails.

## Enabling DNSSEC

1. Open a managed primary zone.
2. Change DNSSEC policy from `none` to `default`.
3. Wait until the DNSSEC status endpoint reports `signed: true` and returns DS data.
4. Publish the returned DS record at the parent zone/registrar.
5. Verify delegation and validation externally before considering the rollout complete.

## Disabling DNSSEC safely

Do not move a delegated signed zone directly from `default` to `none` while a parent DS exists.

1. Change the policy to `insecure`.
2. Remove the DS record from the parent/registrar, or allow CDS/CDNSKEY automation to remove it when supported.
3. Confirm that the parent no longer publishes the DS record and the transition has completed.
4. Change the policy from `insecure` to `none`.
