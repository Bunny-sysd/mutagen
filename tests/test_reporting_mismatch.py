import os
import json
import tempfile
from mutagen.state import ProgramContext, CrashPayload, VulnerabilityDetail
from mutagen.reporter import save_crash_report


def test_agent_mode_reporting_mismatch_fix():
    context = ProgramContext(
        target_path="test_target.c",
        language="c",
        os_platform="windows",
        source_code="int main() { return 0; }",
        vulnerabilities=[
            VulnerabilityDetail(
                vuln_type="Integer Overflow",
                cwe="CWE-190",
                severity="high",
                line_number=200,
                code_snippet="width * height",
                metadata={"reason": "Generic heuristic warning"}
            )
        ],
        active_payloads=[
            CrashPayload(args=["poc1.png"], exit_code=0, crash_type=None),
            CrashPayload(args=["poc2.png"], exit_code=0, crash_type=None),
        ]
    )

    # Filter dynamic crashes
    dynamic_crashes = [p for p in context.active_payloads if p.crash_type is not None]
    assert len(dynamic_crashes) == 0

    # Test save_crash_report with static_only=True
    with tempfile.TemporaryDirectory() as tmpdir:
        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            static_finding = {
                "args": ["N/A"],
                "return_code": 0,
                "crash_type": "Static Triage Finding (Header/Compilation missing)",
                "vuln_type": "Integer Overflow",
                "cwe": "CWE-190"
            }
            json_file, html_file = save_crash_report(
                [static_finding],
                target_name="test_target.c",
                total_tested=len(context.active_payloads),
                static_only=True
            )
            assert os.path.exists(json_file)
            with open(json_file, "r") as f:
                report_data = json.load(f)

            assert report_data["total_crashes_found"] == 0
            assert report_data["crash_rate"] == "0%"
            assert report_data["static_only"] is True
        finally:
            os.chdir(original_cwd)
