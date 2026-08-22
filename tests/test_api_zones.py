from sqlalchemy import select

from backend.app.models import Record, Zone


def test_create_zone_and_records(client, auth_headers, db):
    response = client.post("/api/v1/zones", headers=auth_headers, json={"name":"example.com","default_ttl":3600})
    assert response.status_code == 201, response.text
    zone = response.json()
    assert zone["serial"] >= 2026082201
    version = zone["version"]

    cases = [
        {"name":"www","type":"A","value":"192.0.2.10","ttl":3600},
        {"name":"v6","type":"AAAA","value":"2001:db8::10","ttl":3600},
        {"name":"alias","type":"CNAME","value":"www.example.com.","ttl":3600},
        {"name":"@","type":"MX","value":"mail.example.com.","priority":10,"ttl":3600},
        {"name":"_sip._tcp","type":"SRV","value":"sip.example.com.","priority":10,"weight":5,"port":5060,"ttl":3600},
        {"name":"@","type":"TXT","value":"v=spf1 -all","ttl":3600},
        {"name":"@","type":"CAA","value":'0 issue "letsencrypt.org"',"ttl":3600},
    ]
    for payload in cases:
        payload["zone_version"] = version
        record_response = client.post("/api/v1/zones/example.com/records", headers=auth_headers, json=payload)
        assert record_response.status_code == 201, record_response.text
        current = client.get("/api/v1/zones/example.com", headers=auth_headers).json()
        version = current["version"]

    listed = client.get("/api/v1/zones/example.com/records", headers=auth_headers).json()
    types = {item["type"] for item in listed["items"]}
    assert {"A","AAAA","CNAME","MX","SRV","TXT","CAA","NS"} <= types


def test_reverse_zone_and_ptr(client, auth_headers):
    response = client.post("/api/v1/zones/reverse", headers=auth_headers, json={"network":"192.168.50.0/24"})
    assert response.status_code == 201, response.text
    zone = response.json()
    assert zone["name"] == "50.168.192.in-addr.arpa"
    ptr = client.post(f"/api/v1/zones/{zone['name']}/records", headers=auth_headers, json={"name":"10","type":"PTR","value":"host.example.com.","ttl":3600,"zone_version":zone["version"]})
    assert ptr.status_code == 201, ptr.text


def test_duplicate_record_returns_conflict(client, auth_headers):
    zone = client.post("/api/v1/zones", headers=auth_headers, json={"name":"duplicate.test"}).json()
    payload = {"name":"www","type":"A","value":"192.0.2.1","ttl":3600,"zone_version":zone["version"]}
    first = client.post("/api/v1/zones/duplicate.test/records", headers=auth_headers, json=payload)
    assert first.status_code == 201
    version = client.get("/api/v1/zones/duplicate.test", headers=auth_headers).json()["version"]
    payload["zone_version"] = version
    second = client.post("/api/v1/zones/duplicate.test/records", headers=auth_headers, json=payload)
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "RECORD_EXISTS"


def test_optimistic_lock_conflict(client, auth_headers):
    zone = client.post("/api/v1/zones", headers=auth_headers, json={"name":"lock.test"}).json()
    payload = {"name":"a","type":"A","value":"192.0.2.1","ttl":3600,"zone_version":zone["version"]}
    assert client.post("/api/v1/zones/lock.test/records", headers=auth_headers, json=payload).status_code == 201
    conflict = client.post("/api/v1/zones/lock.test/records", headers=auth_headers, json={**payload,"name":"b","value":"192.0.2.2"})
    assert conflict.status_code == 409


def test_delete_record(client, auth_headers):
    zone = client.post("/api/v1/zones", headers=auth_headers, json={"name":"delete.test"}).json()
    record = client.post("/api/v1/zones/delete.test/records", headers=auth_headers, json={"name":"www","type":"A","value":"192.0.2.5","ttl":3600,"zone_version":zone["version"]}).json()
    current = client.get("/api/v1/zones/delete.test", headers=auth_headers).json()
    response = client.delete(f"/api/v1/zones/delete.test/records/{record['id']}?zone_version={current['version']}", headers=auth_headers)
    assert response.status_code == 204, response.text


def test_invalid_ip_is_422(client, auth_headers):
    zone = client.post("/api/v1/zones", headers=auth_headers, json={"name":"invalid.test"}).json()
    response = client.post("/api/v1/zones/invalid.test/records", headers=auth_headers, json={"name":"www","type":"A","value":"300.300.300.300","ttl":3600,"zone_version":zone["version"]})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
