(() => {
  "use strict";

  const root = document.getElementById("ha-replication");
  if (!root) return;

  const body = document.getElementById("ha-replication-body");
  const status = document.getElementById("ha-replication-status");
  const refresh = document.getElementById("ha-refresh");
  const csrf = root.dataset.csrf || "";

  function cell(text) {
    const td = document.createElement("td");
    td.textContent = text == null ? "—" : String(text);
    return td;
  }

  function badge(state) {
    const span = document.createElement("span");
    span.className = "badge me-1 " + (state === "in_sync" ? "text-bg-success" : state === "ahead" ? "text-bg-warning" : "text-bg-danger");
    span.textContent = state || "unknown";
    return span;
  }

  async function transferTest(serverId, zone, type, output) {
    output.textContent = `${type}...`;
    const response = await fetch(`/api/v1/servers/${serverId}/zones/${encodeURIComponent(zone)}/transfer-test?transfer_type=${type}`, {
      method: "POST",
      headers: {"X-CSRF-Token": csrf, "Accept": "application/json"}
    });
    const data = await response.json();
    if (!response.ok) {
      output.textContent = data?.error?.message || `HTTP ${response.status}`;
      return;
    }
    output.textContent = `${type}: ${data.status}${data.rcode ? ` (${data.rcode})` : ""}`;
  }

  function serverCell(zoneName, servers) {
    const td = document.createElement("td");
    if (!servers.length) {
      td.textContent = "—";
      return td;
    }
    servers.forEach((server) => {
      const line = document.createElement("div");
      line.className = "mb-2";
      const name = document.createElement("span");
      name.className = "font-monospace me-2";
      name.textContent = `${server.server} (${server.address})`;
      line.append(name, badge(server.status));
      const serial = document.createElement("span");
      serial.className = "small text-body-secondary me-2";
      serial.textContent = `serial ${server.serial ?? "—"}${server.serial_lag != null ? ` · lag ${server.serial_lag}` : ""}`;
      line.append(serial);

      const result = document.createElement("span");
      result.className = "small text-body-secondary ms-2";
      ["AXFR", "IXFR"].forEach((type) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "btn btn-sm btn-outline-secondary me-1";
        button.textContent = type;
        button.addEventListener("click", () => transferTest(server.server_id, zoneName, type, result));
        line.append(button);
      });
      line.append(result);
      td.append(line);
    });
    return td;
  }

  async function load() {
    refresh.disabled = true;
    status.textContent = "Sprawdzanie SOA...";
    try {
      const response = await fetch("/api/v1/ha/replication", {headers: {"Accept": "application/json"}});
      const data = await response.json();
      if (!response.ok) throw new Error(data?.error?.message || `HTTP ${response.status}`);
      body.replaceChildren();
      data.forEach((zone) => {
        const tr = document.createElement("tr");
        tr.append(cell(zone.zone), cell(zone.zone_type), cell(zone.expected_serial));
        const local = document.createElement("td");
        local.append(badge(zone.local?.status));
        local.append(document.createTextNode(` serial ${zone.local?.serial ?? "—"}${zone.local?.serial_lag != null ? ` · lag ${zone.local.serial_lag}` : ""}`));
        tr.append(local, serverCell(zone.zone, zone.servers || []));
        body.append(tr);
      });
      if (!data.length) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 5;
        td.className = "text-body-secondary";
        td.textContent = "Brak aktywnych stref.";
        tr.append(td);
        body.append(tr);
      }
      status.textContent = `Sprawdzono ${data.length} stref.`;
    } catch (error) {
      status.textContent = `Błąd HA: ${error.message}`;
    } finally {
      refresh.disabled = false;
    }
  }

  refresh.addEventListener("click", load);
  load();
})();
