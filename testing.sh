#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-local}"
cd "$ROOT"

export TESTING=true
export SESSION_SECURE=false
export SECRET_KEY="${SECRET_KEY:-testing-only-secret}"

log() { printf '[testing] %s\n' "$*"; }
require() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }; }

require python3
log "Compiling Python sources"
python3 -m compileall -q backend scripts tests

log "Running unit and API tests"
python3 -m pytest -q

log "Checking shell syntax"
for script in install.sh update.sh uninstall.sh testing.sh scripts/*.sh; do
  bash -n "$script"
done

if command -v shellcheck >/dev/null 2>&1; then
  log "Running shellcheck advisory warnings"
  shellcheck -S warning install.sh update.sh uninstall.sh testing.sh scripts/*.sh || log "ShellCheck warnings reported; continuing to blocking error check"
  log "Running shellcheck blocking error check"
  shellcheck -S error install.sh update.sh uninstall.sh testing.sh scripts/*.sh
else
  log "SKIP shellcheck: command is not installed"
fi

run_isolated_bind_test() {
  if ! command -v named-checkconf >/dev/null 2>&1 || ! command -v named-checkzone >/dev/null 2>&1 || ! command -v named >/dev/null 2>&1 || ! command -v dig >/dev/null 2>&1; then
    log "SKIP isolated BIND E2E: named/named-checkconf/named-checkzone/dig are not all installed"
    return 0
  fi

  local tmp port pid="" privileged_tmp=false
  # Ubuntu confines named with AppArmor and rejects arbitrary /tmp configs.
  # Prefer /var/cache/bind, which the distribution profile permits.
  if [[ -d /var/cache/bind ]] && command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    tmp="$(sudo mktemp -d /var/cache/bind/chrislab-dns-e2e.XXXXXX)"
    sudo chmod 0777 "$tmp"
    privileged_tmp=true
  else
    tmp="$(mktemp -d -t chrislab-dns-e2e.XXXXXX)"
    chmod 0777 "$tmp"
  fi
  port="$((15353 + ($$ % 1000)))"
  cleanup_isolated() {
    local rc=$?
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    if [[ "$privileged_tmp" == true ]]; then
      sudo rm -rf "$tmp"
    else
      rm -rf "$tmp"
    fi
    return "$rc"
  }
  trap cleanup_isolated RETURN

  cat > "$tmp/db.chrislab-e2e.test" <<'ZONE'
$ORIGIN chrislab-e2e.test.
$TTL 300
@ IN SOA ns1.chrislab-e2e.test. hostmaster.chrislab-e2e.test. ( 2026082201 3600 900 1209600 300 )
@ IN NS ns1.chrislab-e2e.test.
ns1 IN A 127.0.0.1
www IN A 192.0.2.123
ZONE
  cat > "$tmp/named.conf" <<CONF
options {
    directory "$tmp";
    listen-on port $port { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    pid-file "$tmp/named.pid";
    session-keyfile "$tmp/session.key";
    managed-keys-directory "$tmp";
};
zone "chrislab-e2e.test" { type primary; file "$tmp/db.chrislab-e2e.test"; };
CONF
  chmod 0644 "$tmp/named.conf" "$tmp/db.chrislab-e2e.test"

  cp -a "$tmp/named.conf" "$tmp/named.conf.snapshot"
  cp -a "$tmp/db.chrislab-e2e.test" "$tmp/db.chrislab-e2e.test.snapshot"
  named-checkzone chrislab-e2e.test "$tmp/db.chrislab-e2e.test" >/dev/null
  named-checkconf -z "$tmp/named.conf" >/dev/null
  named -g -c "$tmp/named.conf" >"$tmp/named.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 30); do
    if dig @127.0.0.1 -p "$port" www.chrislab-e2e.test A +short +time=1 +tries=1 2>/dev/null | grep -Fxq '192.0.2.123'; then
      log "Isolated BIND E2E passed"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$tmp/named.log" >&2
      return 1
    fi
    sleep 0.2
  done
  cat "$tmp/named.log" >&2
  echo "Isolated BIND did not answer the expected record" >&2
  return 1
}

run_installed_test() {
  require curl
  require dig
  local base token zone backup_json backup_id zone_json version record_json current restore_done=0
  base="${BASE_URL:-http://127.0.0.1}"
  token="${TEST_API_TOKEN:-}"
  if [[ -z "$token" ]]; then
    echo "TEST_API_TOKEN is required for ./testing.sh --installed" >&2
    exit 2
  fi
  zone="chrislab-e2e-$RANDOM-$$.test"

  api() {
    local method=$1 path=$2 body=${3:-}
    if [[ -n "$body" ]]; then
      curl --silent --show-error --fail-with-body -X "$method" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' --data "$body" "$base$path"
    else
      curl --silent --show-error --fail-with-body -X "$method" -H "Authorization: Bearer $token" "$base$path"
    fi
  }

  backup_json="$(api POST /api/v1/backups '{"reason":"testing.sh pre-E2E snapshot"}')"
  backup_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$backup_json")"
  cleanup_installed() {
    local rc=$?
    if [[ "$restore_done" -eq 0 && -n "${backup_id:-}" ]]; then
      if api POST "/api/v1/backups/$backup_id/restore" '{}' >/dev/null; then
        restore_done=1
        log "Original BIND/application state restored from backup $backup_id"
      else
        echo "CRITICAL: automatic test restore failed for backup $backup_id" >&2
        rc=1
      fi
    fi
    return "$rc"
  }
  trap cleanup_installed RETURN

  log "Installed E2E: validating current BIND configuration"
  api POST /api/v1/bind/validate '{}' >/dev/null
  zone_json="$(api POST /api/v1/zones "{\"name\":\"$zone\",\"default_ttl\":300}")"
  version="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' <<<"$zone_json")"
  record_json="$(api POST "/api/v1/zones/$zone/records" "{\"name\":\"www\",\"type\":\"A\",\"value\":\"192.0.2.123\",\"ttl\":300,\"zone_version\":$version}")"
  test -n "$record_json"
  api POST /api/v1/bind/reload '{}' >/dev/null
  current="$(dig @127.0.0.1 "www.$zone" A +short +time=2 +tries=2)"
  [[ "$current" == *"192.0.2.123"* ]] || { echo "dig returned unexpected answer: $current" >&2; return 1; }
  version="$(api GET "/api/v1/zones/$zone" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
  record_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$record_json")"
  api DELETE "/api/v1/zones/$zone/records/$record_id?zone_version=$version" >/dev/null
  version="$(api GET "/api/v1/zones/$zone" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
  api DELETE "/api/v1/zones/$zone?zone_version=$version" >/dev/null
  api POST "/api/v1/backups/$backup_id/restore" '{}' >/dev/null
  restore_done=1
  log "Installed API → BIND9 → dig → cleanup/restore E2E passed"
}

run_isolated_bind_test
if [[ "$MODE" == "--installed" ]]; then
  run_installed_test
elif [[ "$MODE" != "local" ]]; then
  echo "Usage: ./testing.sh [--installed]" >&2
  exit 2
fi

log "All executable checks completed"
