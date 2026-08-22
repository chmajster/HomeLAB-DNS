(() => {
  'use strict';
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const alertHost = document.getElementById('alert-host');

  function applyTheme() {
    const root = document.documentElement;
    const selected = root.dataset.userTheme || 'system';
    const actual = selected === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : selected;
    root.setAttribute('data-bs-theme', actual);
  }
  applyTheme();
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme);

  function showAlert(message, kind = 'danger') {
    if (!alertHost) return;
    const node = document.createElement('div');
    node.className = `alert alert-${kind} alert-dismissible fade show`;
    node.setAttribute('role', 'alert');
    node.append(document.createTextNode(message));
    const close = document.createElement('button');
    close.className = 'btn-close'; close.type = 'button'; close.dataset.bsDismiss = 'alert';
    node.append(close); alertHost.prepend(node);
  }

  async function api(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', csrf);
    if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    const response = await fetch(url, {...options, headers, credentials: 'same-origin'});
    if (response.status === 204) return null;
    const contentType = response.headers.get('content-type') || '';
    const body = contentType.includes('application/json') ? await response.json() : await response.text();
    if (!response.ok) {
      const error = body?.error;
      throw new Error(error ? `${error.message}${error.details ? `: ${typeof error.details === 'string' ? error.details : JSON.stringify(error.details)}` : ''}` : String(body));
    }
    return body;
  }

  function valueFromInput(input) {
    if (input.type === 'number') return input.value === '' ? null : Number(input.value);
    if (input.type === 'checkbox') return input.checked;
    return input.value === '' ? null : input.value;
  }

  function formToObject(form) {
    const data = {};
    for (const input of form.elements) {
      if (!input.name || input.disabled || input.type === 'submit' || input.type === 'button') continue;
      data[input.name] = valueFromInput(input);
    }
    return data;
  }

  document.querySelectorAll('[data-api-post]').forEach(button => button.addEventListener('click', async () => {
    if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return;
    try {
      const body = button.dataset.apiJson ? JSON.stringify(JSON.parse(button.dataset.apiJson)) : undefined;
      await api(button.dataset.apiPost, {method: 'POST', body});
      location.reload();
    } catch (error) { showAlert(error.message); }
  }));


  document.querySelectorAll('[data-zone-copy]').forEach(button => button.addEventListener('click', async () => {
    const name = prompt(`Copy ${button.dataset.zone} as:`);
    if (!name) return;
    try {
      await api(`/api/v1/zones/${encodeURIComponent(button.dataset.zone)}/copy?new_name=${encodeURIComponent(name)}`, {method:'POST'});
      location.reload();
    } catch (error) { showAlert(error.message); }
  }));

  document.querySelectorAll('[data-zone-toggle]').forEach(button => button.addEventListener('click', async () => {
    const enabled = button.dataset.enabled !== 'true';
    try {
      await api(`/api/v1/zones/${encodeURIComponent(button.dataset.zone)}`, {method:'PUT', body:JSON.stringify({version:Number(button.dataset.version), enabled})});
      location.reload();
    } catch (error) { showAlert(error.message); }
  }));

  document.getElementById('zone-import-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const zoneName = String(data.get('zone_name') || '');
    data.delete('zone_name');
    try {
      await api(`/api/v1/zones/import/file?zone_name=${encodeURIComponent(zoneName)}`, {method:'POST', body:data});
      location.reload();
    } catch (error) { showAlert(error.message); }
  });

  document.querySelectorAll('[data-api-delete]').forEach(button => button.addEventListener('click', async () => {
    if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return;
    try { await api(button.dataset.apiDelete, {method: 'DELETE'}); location.reload(); }
    catch (error) { showAlert(error.message); }
  }));

  document.querySelectorAll('form[data-json-form]').forEach(form => form.addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const payload = formToObject(form);
      await api(form.dataset.endpoint, {method: form.dataset.method || 'POST', body: JSON.stringify(payload)});
      location.reload();
    } catch (error) { showAlert(error.message); }
  }));

  const recordModal = document.getElementById('recordModal');
  const recordForm = document.getElementById('record-form');
  const recordType = document.getElementById('record-type');
  function updateRecordFields() {
    if (!recordType) return;
    const type = recordType.value;
    document.querySelectorAll('.record-extra').forEach(el => el.classList.add('d-none'));
    if (['MX','SRV'].includes(type)) document.querySelector('.record-extra.priority')?.classList.remove('d-none');
    if (type === 'SRV') {
      document.querySelector('.record-extra.weight')?.classList.remove('d-none');
      document.querySelector('.record-extra.port')?.classList.remove('d-none');
    }
  }
  recordType?.addEventListener('change', updateRecordFields); updateRecordFields();

  function openRecordEditor(data, id = null) {
    if (!recordModal || !recordForm) return;
    recordForm.dataset.recordId = id || '';
    for (const [key, value] of Object.entries(data || {})) {
      const input = recordForm.elements.namedItem(key);
      if (input) input.value = value ?? '';
    }
    if (!data?.name) recordForm.elements.namedItem('name').value = '@';
    if (!data?.ttl) recordForm.elements.namedItem('ttl').value = '3600';
    updateRecordFields();
    document.getElementById('record-preview')?.classList.add('d-none');
    bootstrap.Modal.getOrCreateInstance(recordModal).show();
  }
  document.querySelectorAll('[data-record-new]').forEach(btn => btn.addEventListener('click', () => { recordForm?.reset(); openRecordEditor({}, null); }));
  document.querySelectorAll('[data-record-edit]').forEach(btn => btn.addEventListener('click', () => openRecordEditor(JSON.parse(btn.dataset.record), JSON.parse(btn.dataset.record).id)));
  document.querySelectorAll('[data-record-duplicate]').forEach(btn => btn.addEventListener('click', () => openRecordEditor(JSON.parse(btn.dataset.record), null)));

  function recordPayload() {
    const payload = formToObject(recordForm);
    payload.zone_version = Number(recordModal.dataset.version);
    return payload;
  }
  recordForm?.addEventListener('submit', async event => {
    event.preventDefault();
    const zone = recordModal.dataset.zone;
    const recordId = recordForm.dataset.recordId;
    const endpoint = recordId ? `/api/v1/zones/${encodeURIComponent(zone)}/records/${recordId}` : `/api/v1/zones/${encodeURIComponent(zone)}/records`;
    try { await api(endpoint, {method: recordId ? 'PUT' : 'POST', body: JSON.stringify(recordPayload())}); location.reload(); }
    catch (error) { showAlert(error.message); }
  });
  document.getElementById('preview-record')?.addEventListener('click', async () => {
    try {
      const zone = recordModal.dataset.zone;
      const recordId = recordForm.dataset.recordId;
      const endpoint = recordId ? `/api/v1/zones/${encodeURIComponent(zone)}/records/${recordId}/preview` : `/api/v1/zones/${encodeURIComponent(zone)}/records/preview`;
      const result = await api(endpoint, {method:'POST', body:JSON.stringify(recordPayload())});
      const output = document.getElementById('record-preview'); output.textContent = result.diff || 'No textual difference.'; output.classList.remove('d-none');
    } catch (error) { showAlert(error.message); }
  });

  const filter = document.getElementById('record-filter');
  const typeFilter = document.getElementById('record-type-filter');
  function filterRecords() {
    const query = (filter?.value || '').toLowerCase(); const type = typeFilter?.value || '';
    document.querySelectorAll('#records-table tbody tr[data-search]').forEach(row => {
      row.hidden = !row.dataset.search.toLowerCase().includes(query) || (type && row.dataset.type !== type);
    });
  }
  filter?.addEventListener('input', filterRecords); typeFilter?.addEventListener('change', filterRecords);
  document.getElementById('select-all')?.addEventListener('change', event => document.querySelectorAll('.record-check').forEach(x => { x.checked = event.target.checked; }));

  async function bulk(operation, ttl = null) {
    const buttonId = operation === 'delete' ? 'bulk-delete' : operation === 'export' ? 'bulk-export' : 'bulk-ttl';
    const button = document.getElementById(buttonId);
    const ids = [...document.querySelectorAll('.record-check:checked')].map(x => Number(x.value));
    if (!ids.length) { showAlert('Select at least one record.', 'warning'); return; }
    const payload = {record_ids: ids, operation, ttl, zone_version: Number(button.dataset.version)};
    try {
      const result = await api(`/api/v1/zones/${encodeURIComponent(button.dataset.zone)}/records/bulk`, {method:'POST', body:JSON.stringify(payload)});
      if (operation === 'export') {
        const blob = new Blob([JSON.stringify(result.records, null, 2)], {type:'application/json'});
        const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `${button.dataset.zone}-records.json`; link.click(); URL.revokeObjectURL(link.href);
      } else { location.reload(); }
    } catch (error) { showAlert(error.message); }
  }
  document.getElementById('bulk-delete')?.addEventListener('click', () => { if (confirm('Delete selected records?')) bulk('delete'); });
  document.getElementById('bulk-ttl')?.addEventListener('click', () => { const value = prompt('New TTL (30-604800):'); if (value !== null) bulk('ttl', Number(value)); });
  document.getElementById('bulk-export')?.addEventListener('click', () => bulk('export'));

  document.getElementById('preview-zone')?.addEventListener('click', async () => {
    const form = document.getElementById('zone-settings-form');
    const output = document.getElementById('zone-preview');
    try {
      const result = await api(form.dataset.previewEndpoint, {method:'POST', body:JSON.stringify(formToObject(form))});
      output.textContent = result.diff || 'No textual difference.'; output.classList.remove('d-none');
    } catch (error) { showAlert(error.message); }
  });

  const lookupForm = document.getElementById('lookup-form');
  lookupForm?.addEventListener('submit', async event => {
    event.preventDefault(); const output = document.getElementById('lookup-result');
    try { const result = await api('/api/v1/tools/lookup', {method:'POST', body:JSON.stringify(formToObject(lookupForm))}); output.textContent = JSON.stringify(result, null, 2); output.classList.remove('d-none'); }
    catch (error) { showAlert(error.message); }
  });

  const logsForm = document.getElementById('logs-form'); let loadedLogs = '';
  async function loadLogs() {
    if (!logsForm) return;
    const query = new URLSearchParams(formToObject(logsForm));
    try { const result = await api(`/api/v1/bind/logs?${query}`); loadedLogs = result.logs || ''; document.getElementById('logs-result').textContent = loadedLogs || 'No log entries.'; }
    catch (error) { showAlert(error.message); }
  }
  logsForm?.addEventListener('submit', event => { event.preventDefault(); loadLogs(); });
  if (logsForm) loadLogs();
  document.getElementById('logs-search')?.addEventListener('input', event => {
    const q = event.target.value.toLowerCase(); document.getElementById('logs-result').textContent = loadedLogs.split('\n').filter(line => line.toLowerCase().includes(q)).join('\n');
  });
  document.getElementById('download-logs')?.addEventListener('click', () => {
    const blob = new Blob([loadedLogs], {type:'text/plain'}); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'bind9.log'; a.click(); URL.revokeObjectURL(a.href);
  });

  document.querySelectorAll('[data-user-save]').forEach(button => button.addEventListener('click', async () => {
    const id = button.dataset.userSave;
    const role = document.querySelector(`[data-user-role="${id}"]`)?.value;
    const enabledControl = document.querySelector(`[data-user-enabled="${id}"]`);
    const enabled = enabledControl ? enabledControl.checked : true;
    try { await api(`/api/v1/users/${id}`, {method:'PUT', body:JSON.stringify({role, enabled})}); location.reload(); }
    catch (error) { showAlert(error.message); }
  }));
  document.querySelectorAll('[data-user-password]').forEach(button => button.addEventListener('click', async () => {
    const password = prompt(`New password for ${button.dataset.username} (minimum 12 characters):`);
    if (!password) return;
    try { await api(`/api/v1/users/${button.dataset.userPassword}/password`, {method:'PUT', body:JSON.stringify({password})}); showAlert('Password updated.', 'success'); }
    catch (error) { showAlert(error.message); }
  }));

  const tokenForm = document.getElementById('token-form');
  tokenForm?.addEventListener('submit', async event => {
    event.preventDefault(); const form = new FormData(tokenForm); const permissions = form.getAll('permissions');
    const expires = form.get('expires_at'); const payload = {name: form.get('name'), permissions, expires_at: expires || null};
    try {
      const result = await api('/api/v1/tokens', {method:'POST', body:JSON.stringify(payload)});
      const host = document.getElementById('token-secret-host'); host.replaceChildren();
      const alert = document.createElement('div'); alert.className = 'alert alert-warning mt-3';
      const title = document.createElement('strong'); title.textContent = 'Copy this token now. It will not be shown again: '; alert.append(title);
      const code = document.createElement('code'); code.textContent = result.token; alert.append(code); host.append(alert);
      bootstrap.Modal.getInstance(document.getElementById('tokenModal'))?.hide();
    } catch (error) { showAlert(error.message); }
  });

  document.getElementById('sync-scan')?.addEventListener('click', async () => {
    try { const result = await api('/api/v1/sync'); document.getElementById('sync-result').textContent = JSON.stringify(result, null, 2); }
    catch (error) { showAlert(error.message); }
  });
  document.getElementById('sync-import')?.addEventListener('click', async () => {
    if (!confirm('Import missing primary zones as externally managed, read-only entries?')) return;
    try { const result = await api('/api/v1/sync/import', {method:'POST'}); document.getElementById('sync-result').textContent = JSON.stringify(result, null, 2); }
    catch (error) { showAlert(error.message); }
  });
})();
