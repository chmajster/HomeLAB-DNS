import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("named-checkzone") is None, reason="named-checkzone is not installed in the test environment")
def test_named_checkzone_accepts_valid_zone(tmp_path: Path):
    zone = tmp_path / "db.example.test"
    zone.write_text("""$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1.example.test. hostmaster.example.test. ( 2026082201 3600 900 1209600 300 )\n@ IN NS ns1.example.test.\nns1 IN A 127.0.0.1\nwww IN A 192.0.2.10\n""", encoding="utf-8")
    proc = subprocess.run(["named-checkzone", "example.test", str(zone)], capture_output=True, text=True, shell=False, check=False)
    assert proc.returncode == 0, proc.stderr + proc.stdout
