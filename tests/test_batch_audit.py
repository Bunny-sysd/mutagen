import os
from unittest.mock import patch

from batch_audit import find_newest_report, generate_html_report, get_supported_files


def test_get_supported_files(tmp_path):
    # Create mock directories and files
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # Supported files
    c_file = src_dir / "target.c"
    c_file.write_text("int main() {}")

    js_file = src_dir / "app.js"
    js_file.write_text("console.log();")

    # Excluded files/folders
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    hidden_file = venv_dir / "ignored.c"
    hidden_file.write_text("int main() {}")

    unsupported_file = src_dir / "data.txt"
    unsupported_file.write_text("hello")

    discovered = get_supported_files(str(tmp_path))

    # Convert paths to relative for easier assertion
    rel_paths = [os.path.relpath(p, tmp_path) for p in discovered]

    assert "src\\target.c" in rel_paths or "src/target.c" in rel_paths
    assert "src\\app.js" in rel_paths or "src/app.js" in rel_paths
    assert len(discovered) == 2


@patch("glob.glob")
@patch("os.path.getmtime")
def test_find_newest_report(mock_getmtime, mock_glob):
    mock_glob.return_value = [
        "crashes/crash_report_target_20260629_120000.json",
        "crashes/crash_report_target_20260629_130000.json"
    ]
    # Newer file has larger timestamp
    mock_getmtime.side_effect = [1000.0, 2000.0]

    newest = find_newest_report("target", start_time=1500.0)
    assert newest == "crashes/crash_report_target_20260629_130000.json"


def test_generate_html_report(tmp_path):
    output_file = tmp_path / "batch_report.html"

    mock_results = [
        {
            "file": "targets/01_overflow.c",
            "status": "success",
            "findings": [
                {
                    "vuln_type": "buffer_overflow",
                    "severity": "critical",
                    "cwe": "CWE-120",
                    "reason": "strcpy vulnerability",
                    "payload": "A * 100"
                }
            ]
        },
        {
            "file": "targets/02_clean.js",
            "status": "success",
            "findings": []
        }
    ]

    generate_html_report(mock_results, str(output_file))

    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "Mutagen Unified Security Dashboard" in content
    assert "01_overflow.c" in content
    assert "02_clean.js" in content
    assert "critical" in content.lower()
