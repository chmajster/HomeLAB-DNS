(() => {
  'use strict';

  const STORAGE_KEY = 'chrislab-language';
  const SUPPORTED = new Set(['pl', 'en']);

  const catalog = [
    ['Przegląd', 'Overview'],
    ['Pulpit', 'Dashboard'],
    ['Strefy', 'Zones'],
    ['Rekordy', 'Records'],
    ['Wyszukiwanie DNS', 'DNS Lookup'],
    ['Synchronizuj', 'Synchronize'],
    ['Infrastruktura', 'Infrastructure'],
    ['Serwer DHCP', 'DHCP Server'],
    ['Platforma DNS', 'DNS Platform'],
    ['Operacje', 'Operations'],
    ['Kopie zapasowe', 'Backups'],
    ['Logi', 'Logs'],
    ['Dziennik audytu', 'Audit Log'],
    ['Administracja', 'Administration'],
    ['Tokeny API', 'API Tokens'],
    ['Użytkownicy', 'Users'],
    ['Bezpieczeństwo / 2FA', 'Security / 2FA'],
    ['Ustawienia', 'Settings'],
    ['Dokumentacja API', 'API Docs'],
    ['Panel sterowania', 'Control plane'],
    ['Wyloguj', 'Log out'],
    ['Otwórz menu', 'Open menu'],
    ['Zamknij', 'Close'],
    ['Główna nawigacja', 'Main navigation'],
    ['Szukaj', 'Search'],
    ['Szukaj strefy, rekordu, IP lub hosta', 'Search zone, record, IP or host'],
    ['Szukaj strefy, rekordu, IP, hosta', 'Search zone, record, IP, host'],
    ['Stan usługi, konfiguracji i danych DNS.', 'Service, configuration and DNS data status.'],
    ['Przegląd operacyjny', 'Operational overview'],
    ['Kondycja usług i najważniejsze metryki platformy DNS.', 'Service health and key DNS platform metrics.'],
    ['Działa', 'Running'],
    ['Zatrzymany', 'Stopped'],
    ['Sprawne', 'Healthy'],
    ['Konfiguracja', 'Configuration'],
    ['Poprawna', 'Valid'],
    ['Niepoprawna', 'Invalid'],
    ['Błędy konfiguracji', 'Config errors'],
    ['Czas działania', 'Uptime'],
    ['Ostatnia zmiana', 'Last change'],
    ['Ostatnie przeładowanie', 'Last reload'],
    ['Ostatnia kopia', 'Last backup'],
    ['Klienci rekursywni', 'Recursive clients'],
    ['Statystyki zapytań DNS', 'DNS query statistics'],
    ['Przeładuj DNS', 'Reload DNS'],
    ['Waliduj konfigurację', 'Validate Configuration'],
    ['Uruchom ponownie BIND9', 'Restart BIND9'],
    ['Utwórz kopię', 'Backup Now'],
    ['Strefy podstawowe i odwrotne DNS. Zewnętrzne strefy pozostają tylko do odczytu do czasu jawnego importu.', 'Primary and reverse DNS zones. Existing external zones remain read-only until explicitly imported.'],
    ['Eksportuj wszystko', 'Export all'],
    ['Importuj strefę', 'Import zone'],
    ['Strefa odwrotna', 'Reverse zone'],
    ['Nowa strefa', 'New zone'],
    ['Filtruj strefy', 'Filter zones'],
    ['Nazwa', 'Name'],
    ['Typ', 'Type'],
    ['Serial', 'Serial'],
    ['Rekordów', 'Records'],
    ['Zmodyfikowano', 'Modified'],
    ['Walidacja', 'Validation'],
    ['wyłączona', 'disabled'],
    ['zewnętrzna', 'external'],
    ['Eksportuj', 'Export'],
    ['Wyłącz', 'Disable'],
    ['Włącz', 'Enable'],
    ['Kopiuj', 'Copy'],
    ['Usuń', 'Delete'],
    ['Brak stref.', 'No zones.'],
    ['Nazwa strefy', 'Zone name'],
    ['Domyślny TTL', 'Default TTL'],
    ['Anuluj', 'Cancel'],
    ['Utwórz', 'Create'],
    ['Sieć IPv4', 'IPv4 network'],
    ['Importuj strefę BIND', 'Import BIND zone'],
    ['Plik strefy', 'Zone file'],
    ['Waliduj i importuj', 'Validate and import'],
    ['Globalny widok rekordów DNS.', 'Global DNS records view.'],
    ['Strefa', 'Zone'],
    ['Wartość', 'Value'],
    ['Nie znaleziono rekordów.', 'No records found.'],
    ['Wygląd', 'Appearance'],
    ['Motyw', 'Theme'],
    ['Jasny', 'Light'],
    ['Ciemny', 'Dark'],
    ['Systemowy', 'System'],
    ['Zapisz', 'Save'],
    ['Język interfejsu', 'Interface language'],
    ['Polski', 'Polish'],
    ['Angielski', 'English'],
    ['Lokalne konto aplikacji', 'Local application account'],
    ['Bieżące hasło', 'Current password'],
    ['Nowa nazwa użytkownika', 'New username'],
    ['Nowe hasło', 'New password'],
    ['Zmień dane lokalnego konta', 'Change local credentials'],
    ['Źródło uwierzytelniania', 'Authentication source'],
    ['Tryb uwierzytelniania', 'Authentication mode'],
    ['Linux / PAM', 'Linux / PAM'],
    ['Konfiguracja LDAP', 'LDAP configuration'],
    ['Adres LDAP', 'LDAP URL'],
    ['Weryfikuj certyfikat TLS', 'Verify TLS certificate'],
    ['Bazowy DN', 'Base DN'],
    ['Filtr użytkownika', 'User filter'],
    ['DN konta bind', 'Bind DN'],
    ['Hasło konta bind', 'Bind password'],
    ['Usuń zapisane hasło bind', 'Clear stored bind password'],
    ['Domyślna rola dla nowych użytkowników LDAP', 'Default role for new LDAP users'],
    ['Tylko odczyt', 'Read Only'],
    ['Operator', 'Operator'],
    ['Administrator', 'Administrator'],
    ['Zapisz ustawienia uwierzytelniania', 'Save authentication settings'],
    ['Testuj zapisane połączenie LDAP', 'Test saved LDAP connection'],
    ['Zaloguj', 'Sign in'],
    ['Użytkownik', 'Username'],
    ['Hasło', 'Password'],
    ['Panel zarządzania BIND9', 'BIND9 management panel'],
    ['Tryb logowania', 'Login mode'],
    ['konto lokalne aplikacji', 'local application account'],
    ['Uruchom', 'Start'],
    ['Zatrzymaj', 'Stop'],
    ['Uruchom ponownie', 'Restart'],
    ['Włącz + uruchom', 'Enable + Start'],
    ['Wyłącz + zatrzymaj', 'Disable + Stop'],
    ['Ustawienia globalne', 'Global settings'],
    ['Zapisz draft', 'Save draft'],
    ['Wdrożenie i backup', 'Deployment and backup'],
    ['Waliduj', 'Validate'],
    ['Zastosuj', 'Apply'],
    ['Importuj aktywnego Kea', 'Import active Kea'],
    ['Backupy konfiguracji', 'Configuration backups'],
    ['Brak backupów.', 'No backups.'],
    ['Subnety', 'Subnets'],
    ['Dodaj subnet', 'Add subnet'],
    ['Usuń subnet', 'Delete subnet'],
    ['Pule', 'Pools'],
    ['Rezerwacje', 'Reservations'],
    ['Opcje subnetu', 'Subnet options'],
    ['Brak pul.', 'No pools.'],
    ['Brak rezerwacji.', 'No reservations.'],
    ['Brak opcji.', 'No options.'],
    ['Dodaj', 'Add'],
    ['Przywróć', 'Restore']
  ];

  const lookup = new Map();
  for (const [pl, en] of catalog) {
    lookup.set(pl, {pl, en});
    lookup.set(en, {pl, en});
  }

  function resolveLanguage() {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (SUPPORTED.has(stored)) return stored;
    return (navigator.language || '').toLowerCase().startsWith('pl') ? 'pl' : 'en';
  }

  function translated(value, language) {
    const entry = lookup.get(value.trim());
    return entry ? entry[language] : null;
  }

  function translateTextNode(node, language) {
    const raw = node.nodeValue || '';
    const value = translated(raw, language);
    if (!value) return;
    const start = raw.match(/^\s*/)?.[0] || '';
    const end = raw.match(/\s*$/)?.[0] || '';
    node.nodeValue = `${start}${value}${end}`;
  }

  function translateElement(element, language) {
    for (const attr of ['placeholder', 'aria-label', 'title']) {
      const raw = element.getAttribute?.(attr);
      if (!raw) continue;
      const value = translated(raw, language);
      if (value) element.setAttribute(attr, value);
    }

    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(node => translateTextNode(node, language));
  }

  function translatePage(language) {
    document.documentElement.lang = language;
    document.documentElement.dataset.language = language;

    const selectors = [
      '.sidebar-nav', '.app-topbar', '.auth-shell',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'button', 'label', 'th', '.ui-eyebrow', '.ui-subtitle',
      '.form-text', '.alert', '.badge', '.nav-link', '.modal-title', '.modal-footer'
    ];
    document.querySelectorAll(selectors.join(',')).forEach(element => translateElement(element, language));
    document.querySelectorAll('input[placeholder], textarea[placeholder], [aria-label], [title]').forEach(element => translateElement(element, language));

    document.querySelectorAll('[data-language-switcher]').forEach(select => { select.value = language; });
  }

  function setLanguage(language) {
    if (!SUPPORTED.has(language)) return;
    localStorage.setItem(STORAGE_KEY, language);
    translatePage(language);
  }

  function createAnonymousSwitcher(language) {
    if (document.querySelector('[data-language-switcher]')) return;
    const wrapper = document.createElement('div');
    wrapper.className = 'language-floating';
    wrapper.innerHTML = `
      <label class="language-switcher" title="Interface language">
        <i class="bi bi-translate" aria-hidden="true"></i>
        <select class="language-select" data-language-switcher aria-label="Interface language">
          <option value="pl">PL</option>
          <option value="en">EN</option>
        </select>
      </label>`;
    document.body.append(wrapper);
    wrapper.querySelector('select').value = language;
  }

  function bindSwitchers() {
    document.addEventListener('change', event => {
      const select = event.target.closest?.('[data-language-switcher]');
      if (select) setLanguage(select.value);
    });
  }

  const language = resolveLanguage();
  createAnonymousSwitcher(language);
  bindSwitchers();
  translatePage(language);

  const observer = new MutationObserver(mutations => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        translateElement(node, resolveLanguage());
      }
    }
  });
  observer.observe(document.body, {childList: true, subtree: true});
})();
