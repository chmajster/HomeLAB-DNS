from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_records_workspace_exposes_global_record_creation():
    template = (ROOT / "frontend" / "templates" / "records.html").read_text(encoding="utf-8")
    script = (ROOT / "frontend" / "static" / "records-create.js").read_text(encoding="utf-8")

    assert "'records.write' in permissions" in template
    assert 'id="globalRecordModal"' in template
    assert 'id="global-record-zone"' in template
    assert '/static/records-create.js' in template

    assert "/api/v1/zones?limit=200" in script
    assert "zone.managed && zone.zone_type === 'primary'" in script
    assert "zone_version: zoneVersion" in script
    assert "method: 'POST'" in script
    assert "/records`" in script


def test_dhcp_workspace_exposes_network_provisioning_forms():
    template = (ROOT / "frontend" / "templates" / "dhcp.html").read_text(encoding="utf-8")

    assert '/dhcp/{{ family }}/subnets"' in template
    assert '/dhcp/{{ family }}/subnets/{{ subnet.get(\'id\') }}/pools"' in template
    assert '/dhcp/{{ family }}/subnets/{{ subnet.get(\'id\') }}/reservations"' in template
    assert '/dhcp/{{ family }}/subnets/{{ subnet.get(\'id\') }}/options"' in template
    assert "Dodaj subnet" in template
    assert "Dodaj rezerwację" in template
