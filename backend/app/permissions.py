from __future__ import annotations

ALL_PERMISSIONS = {
    "zones.read",
    "zones.write",
    "records.read",
    "records.write",
    "bind.reload",
    "bind.restart",
    "backups.read",
    "backups.create",
    "backups.restore",
    "audit.read",
    "users.manage",
    "tokens.manage",
    "logs.read",
    "tools.lookup",
    "settings.manage",
    "dhcp.read",
    "dhcp.manage",
}

ROLE_PERMISSIONS = {
    "administrator": set(ALL_PERMISSIONS),
    "operator": {
        "zones.read", "zones.write", "records.read", "records.write",
        "bind.reload", "backups.read", "backups.create", "audit.read",
        "logs.read", "tools.lookup", "dhcp.read", "dhcp.manage",
    },
    "read_only": {
        "zones.read", "records.read", "backups.read", "audit.read", "logs.read", "tools.lookup", "dhcp.read"
    },
}
