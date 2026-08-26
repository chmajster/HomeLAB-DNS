from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_base_template_loads_i18n_assets_and_switcher():
    base = (ROOT / "frontend" / "templates" / "base.html").read_text(encoding="utf-8")
    assert '/static/i18n.js' in base
    assert '/static/ui-polish.css' in base
    assert 'data-language-switcher' in base
    assert '<option value="pl">PL</option>' in base
    assert '<option value="en">EN</option>' in base


def test_i18n_catalog_supports_polish_and_english():
    script = (ROOT / "frontend" / "static" / "i18n.js").read_text(encoding="utf-8")
    assert "new Set(['pl', 'en'])" in script
    assert "chrislab-language" in script
    assert "['Strefy', 'Zones']" in script
    assert "['Ustawienia', 'Settings']" in script
    assert "['Serwer DHCP', 'DHCP Server']" in script
    assert 'document.documentElement.lang = language' in script


def test_ui_polish_css_contains_responsive_language_control():
    styles = (ROOT / "frontend" / "static" / "ui-polish.css").read_text(encoding="utf-8")
    assert '.language-switcher' in styles
    assert '.language-floating' in styles
    assert '@media (max-width: 767.98px)' in styles
    assert '@media (prefers-reduced-motion: reduce)' in styles
