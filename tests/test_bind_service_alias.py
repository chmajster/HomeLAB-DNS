from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_installer_enables_canonical_bind_service_unit() -> None:
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'systemctl show -p Id --value bind9.service' in installer
    assert 'systemctl enable --now "$BIND_SERVICE"' in installer
    assert "systemctl enable --now bind9\n" not in installer
