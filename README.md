# ChrisLab-DNS

ChrisLab-DNS is a production-oriented Web UI and REST API for installing and managing BIND9 on Ubuntu Server and Debian. BIND zone files remain the authoritative DNS source. The application stores management metadata, users, API tokens, audit events and backup metadata in SQLAlchemy; SQLite is the default database and `DATABASE_URL` can later point to PostgreSQL with the appropriate SQLAlchemy driver.

Version: **0.1.1**

## Features

- Idempotent installer for Ubuntu Server 24.04/26.04 and Debian 12/13.
- FastAPI backend, Bootstrap 5 responsive UI and no Node.js build chain.
- Primary/master and IPv4 reverse zones, with data model ready for additional zone types.
- A, AAAA, CNAME, MX, TXT, NS, PTR, SRV and CAA records.
- Automatic SOA serials in `YYYYMMDDNN` form without moving an existing larger serial backwards.
- Per-zone optimistic locking plus process-local zone locks; stale edits return HTTP 409.
- Transactional DNS changes: stage → validate → backup → atomic commit → reload → health check; failure restores the previous files.
- `named-checkzone` and `named-checkconf -z` validation before changes become active.
- Root-owned privileged helper with a restricted sudo rule; the FastAPI process runs as `bind9-web-manager`, never as root.
- Session/cookie authentication for the UI and hashed bearer tokens for REST clients.
- Administrator, Operator and Read Only roles with granular permissions.
- Argon2id password hashes; one-time generated administrator password at first installation.
- CSRF protection, login/API rate limiting, CSP/security headers, validation against command injection/path traversal, and `subprocess(..., shell=False)` for system commands.
- Audit log with user, source IP, action, zone/record, old/new values and result.
- Configuration/database backups, restore validation and safety backup before restore.
- BIND status, version, PID, uptime, zone/client information where exposed by `rndc`, and journal logs with bounded filters.
- DNS lookup and local zone testing via `dig`/dnspython.
- Import/export, full zone archive, reverse-zone wizard, bulk record operations and global search.
- Synchronization view for discovering existing BIND zones without overwriting administrator-managed files.
- OpenAPI at `/docs`, `/redoc` and `/openapi.json`.

## Screens

The UI contains Dashboard, Zones, Records, DNS Lookup, Backups, Logs, Audit Log, API Tokens, Users, Synchronize and Settings views. Capture deployment-specific screenshots after installation so hostnames, zones, IP addresses and audit data can be sanitized before publishing them.

## Architecture

```text
ChrisLab-DNS/
├── backend/
│   └── app/
│       ├── api/            # versioned REST routes
│       ├── services/       # BIND, zone, backup, sync and DNS logic
│       ├── cli.py          # migration/admin/sync/backup CLI
│       ├── models.py       # SQLAlchemy models
│       ├── schemas.py      # Pydantic validation
│       ├── security.py     # Argon2id, tokens, sessions, rate limiting
│       └── main.py         # FastAPI assembly/middleware
├── frontend/
│   ├── templates/          # Jinja2 + Bootstrap 5
│   └── static/
├── scripts/
│   ├── privileged_helper.py
│   ├── install_config.py
│   ├── backup.sh
│   └── restore.sh
├── config/                 # sudo/helper configuration
├── nginx/
├── systemd/
├── tests/
├── install.sh
├── update.sh
├── uninstall.sh
├── testing.sh
└── VERSION
```

The application does not grant `NOPASSWD: ALL`. `sudo` can only invoke `/usr/local/libexec/bind9-web-manager-helper`; the helper itself has a fixed argparse subcommand set, validates zone names, filenames and allowed roots, and invokes system programs as argument arrays with `shell=False`.

## Supported systems

- Ubuntu Server 24.04 LTS
- Ubuntu Server 26.04 LTS
- Debian 12
- Debian 13

The installer expects systemd, apt and the distribution BIND9 package layout under `/etc/bind`.

## Installation

Clone the repository on the DNS server and run:

```bash
sudo ./install.sh
```

The installer:

1. validates distribution and privileges;
2. runs `apt-get update` and installs BIND9, utilities, Python, nginx, sudo and supporting packages;
3. creates the `bind9-web-manager` system account;
4. makes a one-time pre-install copy of existing `/etc/bind` state;
5. installs the application under `/opt/bind9-web-manager` and creates its virtualenv;
6. generates `/etc/bind9-web-manager.env` with a cryptographically random `SECRET_KEY` only when the file does not already exist;
7. installs and validates the restricted sudo/helper configuration;
8. adds the ChrisLab-managed include only if it is absent, validates it, and rolls that edit back on failure;
9. installs systemd and nginx configuration;
10. initializes/migrates the database and creates the initial `admin` account only if no administrator exists;
11. starts/validates BIND9, the panel and nginx;
12. scans existing BIND configuration for zones that are not yet known to the panel.

On the first installation only, stdout contains:

```text
ONE_TIME_ADMIN_PASSWORD=<generated-secret>
```

The generated password is not stored in plaintext and is not printed again. A repeated `./install.sh` preserves the existing environment file, database, administrator credentials and BIND configuration.

### JSON and silent installation

For unattended provisioning, pass a validated JSON configuration with `--config` (or `--json`) and enable `--silent`:

```bash
sudo ./install.sh \
  --config /root/chrislab-dns-install.json \
  --silent \
  --result-json /root/chrislab-dns-install-result.json
```

`--silent` uses non-interactive package installation and suppresses normal command output. If `--result-json` is provided, successful silent installation writes the final result there with mode `0600` and produces no normal stdout. The result contains the panel URL, administrator creation status, synchronization result, and the one-time generated administrator password when the installer generated one.

A complete template is available as `config/install.example.json`:

```json
{
  "app": {
    "host": "127.0.0.1",
    "port": 8080,
    "data_dir": "/var/lib/bind9-web-manager"
  },
  "bind": {
    "config": "/etc/bind/named.conf",
    "local_config": "/etc/bind/named.conf.local",
    "managed_config": "/etc/bind/named.conf.chrislab",
    "zone_dir": "/etc/bind/zones",
    "allowed_read_roots": ["/etc/bind", "/var/lib/bind", "/var/cache/bind"]
  },
  "security": {
    "session_secure": false,
    "session_samesite": "lax",
    "session_max_age": 28800,
    "auto_backup": true,
    "trusted_hosts": ["dns-server.example.com", "127.0.0.1"],
    "log_level": "INFO"
  },
  "admin": {
    "username": "admin",
    "password_file": "/root/chrislab-dns-admin-password"
  },
  "installation": {
    "sync_existing": true,
    "remove_default_nginx_site": true
  }
}
```

`admin.password_file` is preferred for automated deployments. `admin.password` is also accepted, requires at least 12 characters, and is never written to the application database in plaintext. The installer copies either form into a temporary `/run` file with restrictive permissions before invoking the application CLI. `admin.password` and `admin.password_file` cannot be used together.

The JSON parser is strict: unknown keys, invalid types, unsafe paths, public backend listeners, invalid ports and inconsistent cookie settings are rejected before the application is configured. BIND configuration paths must remain under `/etc/bind`; `allowed_read_roots` can include approved external directories for existing zone files. On an already installed host, the current runtime paths and settings from `/etc/bind9-web-manager.env` take precedence so a repeated provisioning run cannot silently relocate the database or active BIND configuration.

Useful commands:

```bash
./install.sh --help
python3 scripts/install_config.py config/install.example.json --format json
```

## Existing BIND9 installations

Existing configuration is backed up before the panel modifies its include wiring. Existing zone files are not rewritten. Use **Synchronize** to compare BIND discovery with the panel database and import missing primary zones as externally managed/read-only entries. This preserves manual changes and keeps BIND files as the source of truth.

A managed zone has a SHA-256 file fingerprint. If its active file changes outside the panel after synchronization, an attempted panel edit returns `409 ZONE_CHANGED_EXTERNALLY` instead of overwriting the file.

## Configuration

`.env.example` documents the supported environment variables. Production secrets belong in `/etc/bind9-web-manager.env`, not in Git.

```dotenv
APP_HOST=127.0.0.1
APP_PORT=8080
DATABASE_URL=sqlite:////var/lib/bind9-web-manager/database.db
BIND_CONFIG=/etc/bind/named.conf
BIND_ZONE_DIR=/etc/bind/zones
BACKUP_DIR=/var/lib/bind9-web-manager/backups
SESSION_SECURE=true
```

`APP_HOST` should remain `127.0.0.1`; nginx is the public entry point. Set `TRUSTED_HOSTS` to the expected DNS name/IP list in internet-facing installations.

### HTTP in a trusted LAN

The installer initially writes `SESSION_SECURE=false`, because a Secure cookie cannot be used over plain HTTP. This is suitable only for a trusted management LAN. Protect the management network with firewall/VLAN policy.

### HTTPS / Let's Encrypt

For a DNS name that can complete ACME validation:

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d dns.example.com
```

Then set:

```dotenv
SESSION_SECURE=true
TRUSTED_HOSTS=dns.example.com
```

and restart only the panel:

```bash
sudo systemctl restart bind9-web-manager
```

For private/LAN names, use an internal CA or terminate TLS at an existing trusted reverse proxy instead of forcing public Let's Encrypt issuance.

## DNS transaction model

Managed zone changes use this order:

```text
BEGIN
  lock/version check
  render to staging file
  fsync staging file
  named-checkzone
  backup current BIND + application DB
  validate candidate named configuration
  atomic replace (os.replace) + directory fsync
  rndc reconfig/reload
  service/rndc health check
COMMIT
```

On any helper failure after file commit, the helper restores the transaction snapshot and reloads the previous configuration. The SQLAlchemy transaction is rolled back as well.

The panel never edits zone files with `sed` or arbitrary regular expressions. Managed files are rendered from validated DNS models; imported files are parsed with dnspython before they become managed.

## SOA serials

Each successful managed-zone edit increments the SOA serial automatically. For 22 August 2026, the first serial is `2026082201`, then `2026082202`. If the stored serial is already numerically greater than the date-derived value, it is incremented by one.

## Users and permissions

Roles:

- **Administrator** — all permissions.
- **Operator** — zone/record management, reload, backups, logs, audit and lookup; no user/token administration and no BIND restart.
- **Read Only** — read-only DNS, backups, logs, audit and lookup.

Granular permission identifiers include:

```text
zones.read zones.write records.read records.write
bind.reload bind.restart
backups.read backups.create backups.restore
audit.read users.manage tokens.manage logs.read tools.lookup settings.manage
```

An API token cannot exceed the permissions of the user that owns it even if a broader permission list was stored for that token.

## API tokens

Create tokens from **API Tokens**. The full token is returned exactly once. Only its SHA-256 digest and a non-secret prefix are stored. Tokens can have an expiration time, be disabled/revoked, and record `last_used`.

Example:

```bash
curl \
  -H "Authorization: Bearer TOKEN" \
  http://dns-server/api/v1/zones
```

Create a zone:

```bash
curl -X POST \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"example.com","default_ttl":3600}' \
  http://dns-server/api/v1/zones
```

Add an A record using the current `zone_version`:

```bash
curl -X POST \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"www","type":"A","value":"192.0.2.20","ttl":3600,"zone_version":1}' \
  http://dns-server/api/v1/zones/example.com/records
```

Important endpoints:

```text
GET    /api/v1/health
GET    /api/v1/version
GET    /api/v1/status
GET    /api/v1/search?q=...
GET    /api/v1/zones
POST   /api/v1/zones
POST   /api/v1/zones/reverse
POST   /api/v1/zones/import/file
GET    /api/v1/zones/export/all/archive
GET    /api/v1/zones/{zone}
PUT    /api/v1/zones/{zone}
DELETE /api/v1/zones/{zone}
POST   /api/v1/zones/{zone}/copy
GET    /api/v1/zones/{zone}/records
POST   /api/v1/zones/{zone}/records
PUT    /api/v1/zones/{zone}/records/{id}
DELETE /api/v1/zones/{zone}/records/{id}
POST   /api/v1/zones/{zone}/records/bulk
POST   /api/v1/zones/{zone}/test
POST   /api/v1/bind/validate
POST   /api/v1/bind/reload
POST   /api/v1/bind/restart
GET    /api/v1/bind/logs
GET    /api/v1/backups
POST   /api/v1/backups
POST   /api/v1/backups/{id}/restore
GET    /api/v1/audit
POST   /api/v1/tools/lookup
GET    /api/v1/sync
POST   /api/v1/sync/import
```

Lists of zones, records and audit entries support `limit`/`offset`; zones, records and audit also accept `page`/`page_size`. BIND logs accept bounded line/time/level parameters and page/offset controls. `/docs` contains request/response schemas and endpoint permission descriptions.

API errors use one envelope:

```json
{
  "error": {
    "code": "ZONE_VALIDATION_FAILED",
    "message": "Zone validation failed",
    "details": "named-checkzone output"
  }
}
```

## Backups and restore

Automatic backups are stored under `/var/lib/bind9-web-manager/backups`. Each backup contains a SQLite-consistent database copy, metadata, and an HMAC-signed BIND snapshot. The signed snapshot contains BIND configuration plus declared zone files, including zone files located under the configured `/var/lib/bind` or `/var/cache/bind` roots. Common private-key files such as `rndc.key`, `session.key`, `*.private`, PEM and PKCS#12 files are deliberately not copied into downloadable backups; restore preserves such existing secret files in place. The UI shows timestamp, size, reason and user.

Manual scripts:

```bash
sudo ./scripts/backup.sh "before maintenance"
sudo ./scripts/restore.sh BACKUP_ID
```

Restore creates a safety backup first. The privileged helper verifies the BIND snapshot HMAC before trusting any root-level restore input, validates the candidate configuration and primary zone files, and only then writes active files. If final `named-checkconf -z`, reload, or health validation fails, the previous BIND files are restored automatically. A tampered backup is rejected before BIND is modified.

## Update

From a new checkout/release directory:

```bash
sudo ./update.sh
```

The updater backs up application/configuration state, fast-forwards a Git checkout when applicable, updates files/dependencies, runs DB migrations, validates BIND and nginx, then restarts only `bind9-web-manager` and reloads nginx. It does not restart BIND9 when DNS configuration has not changed.

## Uninstall

```bash
sudo ./uninstall.sh
```

The script asks separately about removing the application, database, backups, BIND configuration and BIND packages. Destructive answers default to **No**. Zone files are never recursively deleted by uninstall; removing the panel-managed include leaves zone data on disk.

## Tests

Development checks:

```bash
python3 -m pip install -r backend/requirements.txt -r requirements-dev.txt
./testing.sh
```

`testing.sh` runs Python compilation, unit/API tests, shell syntax, ShellCheck when installed, and an isolated real BIND9 validation/query test when `named`, `named-checkconf`, `named-checkzone` and `dig` exist.

For an already installed server, create a short-lived Administrator API token and run:

```bash
sudo TEST_API_TOKEN='cldns_...' BASE_URL='http://127.0.0.1' ./testing.sh --installed
```

Installed mode creates a backup first, creates a unique `.test` zone through the API, adds an A record, reloads BIND, verifies the answer with `dig`, removes the test data, then restores the original backup. A trap attempts restore on every exit path, including failures.

GitHub Actions installs real BIND9 utilities and ShellCheck on Ubuntu 24.04 and runs the same test entrypoint.

## Security notes

- Keep the management UI off untrusted networks unless HTTPS, host filtering and firewall policy are configured.
- The application system account has no login shell and does not run Uvicorn as root.
- Root operations are isolated in the root-owned helper and sudoers file; there is no arbitrary shell execution interface. The service account is intentionally not a member of the `bind` group.
- User input is validated as DNS names, IP addresses, integer TTL/priority/port values or bounded enum values before reaching system operations.
- Journal access maps UI options to fixed helper arguments; the browser cannot send arbitrary `journalctl` arguments. Helper-based zone reads are restricted to file paths actually declared by `named-checkconf -p`, preventing use of the helper as a generic `/etc/bind` file reader.
- UI state-changing requests use SameSite sessions plus CSRF tokens. API bearer tokens do not depend on cookies.
- Login is rate-limited separately from the general API limiter.
- Jinja autoescaping, CSP, frame denial and content-type sniffing protections are enabled.
- systemd uses `ProtectSystem=strict`, `ProtectHome=true`, private devices/tmp, namespace restrictions and a narrow address-family set. `NoNewPrivileges=false` is intentional because the application must be able to invoke the tightly constrained sudo helper; the application user itself still lacks direct write ownership of `/etc/bind`.
- Never commit `/etc/bind9-web-manager.env`, databases, backups, API tokens, passwords or private keys.

## Troubleshooting

Validate BIND:

```bash
sudo named-checkconf -z /etc/bind/named.conf
sudo rndc status
sudo systemctl status bind9
```

Panel status/logs:

```bash
sudo systemctl status bind9-web-manager
sudo journalctl -u bind9-web-manager --since '30 minutes ago'
sudo nginx -t
```

Check helper policy:

```bash
sudo visudo -cf /etc/sudoers.d/bind9-web-manager
sudo -u bind9-web-manager sudo /usr/local/libexec/bind9-web-manager-helper status
```

If a panel edit returns `ZONE_CHANGED_EXTERNALLY`, do not force the write. Open **Synchronize**, reconcile the file/database state, and only then continue editing.
