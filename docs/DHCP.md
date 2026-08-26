# DHCP server management

ChrisLab DNS can manage Kea DHCPv4 and DHCPv6 from the same Web UI.

## Scope

The `/dhcp` page provides:

- DHCPv4 and DHCPv6 service status;
- start, stop and restart controls;
- enable/start and disable/stop controls;
- interface selection;
- valid, renew, rebind and IPv6 preferred lifetimes;
- authoritative DHCPv4 mode;
- global DNS/domain options;
- subnet creation and deletion;
- pool creation and deletion;
- static reservations using MAC, client-id, DUID or flex-id as appropriate;
- global and per-subnet custom option-data;
- recent memfile leases;
- Kea journal logs;
- import of the active `/etc/kea/kea-dhcp4.conf` or `/etc/kea/kea-dhcp6.conf`;
- full advanced Kea JSON editing;
- explicit Validate and Apply operations.

The REST API is available under `/api/v1/dhcp` and uses the `dhcp.read` and `dhcp.manage` permissions.

## Safe apply workflow

A Web UI edit changes only the draft stored in the ChrisLab metadata database. The active Kea configuration changes only when Apply is selected.

Apply performs:

1. strict JSON structure and dangerous-key checks;
2. staging into the application staging directory;
3. `kea-dhcp4 -t` or `kea-dhcp6 -t` validation;
4. a root-owned timestamped backup of the previous Kea configuration;
5. atomic replacement of the target configuration;
6. a second Kea validation against the final path;
7. restart only when the service was already running;
8. automatic rollback if replacement, validation or restart fails.

`hooks-libraries` is intentionally blocked in Web UI/API supplied JSON. Allowing an administrative Web session to select an arbitrary shared object loaded by a privileged service would create an unnecessary code-execution boundary violation.

## Rogue DHCP protection

Installing the DHCP module must not silently introduce a competing DHCP server. `install_dhcp.sh` checks whether each Kea package was already installed before the module installation. Newly added Kea DHCPv4/DHCPv6 services are disabled and stopped after package installation. Existing Kea installations preserve their prior service state.

Use the Web UI in this order for a new server:

1. configure interfaces/subnets/pools;
2. Validate;
3. Apply;
4. Enable + Start.

## Installation

For an existing ChrisLab DNS installation:

```bash
sudo bash ./install_dhcp.sh
```

`update.sh` runs the DHCP module installer automatically with `--no-restart`.

Packages:

- `kea-dhcp4-server`
- `kea-dhcp6-server`

The restricted helper is installed as `/usr/local/libexec/chrislab-dhcp-helper`; its root-owned configuration is `/etc/chrislab-dhcp-helper.conf`.

## Lease backends

The Web UI lease table reads Kea memfile CSV leases under `/var/lib/kea`. Advanced JSON may configure other Kea lease backends such as PostgreSQL or MySQL, but those leases are not directly read by the memfile viewer.

## Advanced configuration

The raw JSON editor intentionally keeps the native Kea document structure (`Dhcp4` or `Dhcp6`). This allows settings not represented by the convenience forms to be managed without replacing the application UI every time Kea adds a new ordinary configuration parameter. The configuration is still validated by the installed Kea binary before Apply.
