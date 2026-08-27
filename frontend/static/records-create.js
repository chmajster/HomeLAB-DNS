(() => {
  'use strict';

  const modal = document.getElementById('globalRecordModal');
  const form = document.getElementById('global-record-form');
  const zoneSelect = document.getElementById('global-record-zone');
  const typeSelect = document.getElementById('global-record-type');
  const errorWrap = document.getElementById('global-record-error-wrap');
  const errorBox = document.getElementById('global-record-error');
  const submitButton = document.getElementById('global-record-submit');
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

  if (!modal || !form || !zoneSelect || !typeSelect) return;

  let zonesLoaded = false;

  function showError(message) {
    errorBox.textContent = message;
    errorWrap.classList.remove('d-none');
  }

  function clearError() {
    errorBox.textContent = '';
    errorWrap.classList.add('d-none');
  }

  async function api(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', csrf);
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');

    const response = await fetch(url, {...options, headers, credentials: 'same-origin'});
    const contentType = response.headers.get('content-type') || '';
    const body = contentType.includes('application/json') ? await response.json() : await response.text();

    if (!response.ok) {
      const error = body?.error;
      const details = error?.details
        ? `: ${typeof error.details === 'string' ? error.details : JSON.stringify(error.details)}`
        : '';
      throw new Error(error ? `${error.message}${details}` : String(body));
    }
    return body;
  }

  async function loadZones() {
    if (zonesLoaded) return;
    zoneSelect.disabled = true;
    zoneSelect.innerHTML = '<option value="">Ładowanie stref…</option>';

    try {
      const result = await api('/api/v1/zones?limit=200');
      const zones = (result.items || []).filter(zone => zone.managed && zone.zone_type === 'primary');
      zoneSelect.replaceChildren();

      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = zones.length ? 'Wybierz strefę…' : 'Brak zarządzanych stref primary';
      zoneSelect.append(placeholder);

      for (const zone of zones) {
        const option = document.createElement('option');
        option.value = zone.name;
        option.textContent = zone.name;
        option.dataset.version = String(zone.version);
        zoneSelect.append(option);
      }

      zonesLoaded = true;
    } catch (error) {
      zoneSelect.replaceChildren();
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'Nie udało się pobrać stref';
      zoneSelect.append(option);
      showError(error.message);
    } finally {
      zoneSelect.disabled = false;
    }
  }

  function updateExtraFields() {
    document.querySelectorAll('.global-record-extra').forEach(element => element.classList.add('d-none'));
    const type = typeSelect.value;
    if (type === 'MX' || type === 'SRV') {
      document.querySelector('.global-record-priority')?.classList.remove('d-none');
    }
    if (type === 'SRV') {
      document.querySelector('.global-record-weight')?.classList.remove('d-none');
      document.querySelector('.global-record-port')?.classList.remove('d-none');
    }
  }

  function optionalNumber(name) {
    const value = form.elements.namedItem(name)?.value;
    return value === '' || value == null ? null : Number(value);
  }

  modal.addEventListener('show.bs.modal', () => {
    clearError();
    loadZones();
    updateExtraFields();
  });

  typeSelect.addEventListener('change', updateExtraFields);

  form.addEventListener('submit', async event => {
    event.preventDefault();
    clearError();

    const selectedZone = zoneSelect.selectedOptions[0];
    const zoneName = selectedZone?.value || '';
    const zoneVersion = Number(selectedZone?.dataset.version || 0);
    if (!zoneName || !zoneVersion) {
      showError('Wybierz zarządzaną strefę DNS.');
      return;
    }

    const payload = {
      name: String(form.elements.namedItem('name').value || '@'),
      type: typeSelect.value,
      value: String(form.elements.namedItem('value').value || ''),
      ttl: Number(form.elements.namedItem('ttl').value || 3600),
      priority: optionalNumber('priority'),
      weight: optionalNumber('weight'),
      port: optionalNumber('port'),
      zone_version: zoneVersion,
    };

    submitButton.disabled = true;
    submitButton.textContent = 'Tworzenie…';
    try {
      await api(`/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      window.location.href = `/zones/${encodeURIComponent(zoneName)}`;
    } catch (error) {
      showError(error.message);
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = 'Utwórz rekord';
    }
  });

  updateExtraFields();
})();
