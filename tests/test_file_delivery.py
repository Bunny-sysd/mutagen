import sys

from mutagen.executor import execute_payload
from mutagen.state import CrashPayload


def test_crash_payload_bytes():
    cp_hex = CrashPayload(raw_bytes_hex="41424344")
    assert cp_hex.payload_bytes == b"ABCD"

    cp_str = CrashPayload(input_data="hello")
    assert cp_str.payload_bytes == b"hello"

def test_execute_payload_file_mode(tmp_path):
    # Create a small C script or test script that expects a file argument
    if sys.platform == "win32":
        py_script = tmp_path / "test_file_target.py"
        py_script.write_text("""
import sys
with open(sys.argv[1], "rb") as f:
    data = f.read()
if b"CRASH_TRIGGER" in data:
    raise ValueError("Target Crashed!")
""")
        res = execute_payload(
            exe_path=str(py_script),
            args=[],
            input_data="CRASH_TRIGGER_DATA",
            delivery_mode="file",
            timeout=5
        )
        assert res["crashed"] is True or res["return_code"] != 0
        assert "ValueError" in res["stderr"] or "Target Crashed" in res["stderr"]
