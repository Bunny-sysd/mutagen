"""
Unit tests for Mutagen's Ground-Truth CVE Validation Mode (--validate-cve).
"""

import pytest
from mutagen.cve_validator import (
    fetch_cve_metadata,
    detect_target_version,
    check_version_affected,
    evaluate_cve_validation_outcome,
)
from mutagen.state import ProgramContext, VulnerabilityDetail, CrashPayload


def test_fetch_cve_metadata_builtin_and_generic():
    # 1. Built-in high fidelity registry
    meta1 = fetch_cve_metadata("CVE-2025-65018")
    assert meta1["cve_id"] == "CVE-2025-65018"
    assert "png_combine_row" in meta1["affected_functions"]
    assert meta1["fixed_version"] == "1.6.51"

    # 2. Arbitrary CVE fallback
    meta2 = fetch_cve_metadata("CVE-2024-99999")
    assert meta2["cve_id"] == "CVE-2024-99999"
    assert "cwe" in meta2


def test_detect_target_version_multilang(tmp_path):
    # C Header Macro
    c_hdr = tmp_path / "png.h"
    c_hdr.write_text('#define PNG_LIBPNG_VER_STRING "1.6.50"\n')
    ver_c = detect_target_version(str(c_hdr), c_hdr.read_text())
    assert ver_c == "1.6.50"

    # Rust Cargo.toml
    cargo_toml = tmp_path / "Cargo.toml"
    cargo_toml.write_text('[package]\nname = "test"\nversion = "0.4.2"\n')
    ver_rs = detect_target_version(str(cargo_toml), cargo_toml.read_text())
    assert ver_rs == "0.4.2"

    # Python
    py_mod = tmp_path / "__init__.py"
    py_mod.write_text('__version__ = "2.1.0"\n')
    ver_py = detect_target_version(str(py_mod), py_mod.read_text())
    assert ver_py == "2.1.0"


def test_version_match_gating():
    meta = {"fixed_version": "1.6.51"}
    
    # 1.6.50 is affected (< 1.6.51)
    is_affected, msg = check_version_affected("1.6.50", meta)
    assert is_affected is True
    assert "confirmed affected" in msg

    # 1.6.51 is patched (>= 1.6.51)
    is_affected, msg = check_version_affected("1.6.51", meta)
    assert is_affected is False
    assert "PATCHED" in msg


def test_evaluate_cve_outcomes():
    cve_meta = {
        "cve_id": "CVE-2025-65018",
        "name": "Heap buffer overflow in png_combine_row",
        "fixed_version": "1.6.51"
    }

    # Case B: Patched target version
    ctx_b = ProgramContext(target_path="dummy.c", language="c", os_platform="linux", source_code="")
    res_b = evaluate_cve_validation_outcome(ctx_b, cve_meta, "1.6.51", is_version_affected=False)
    assert res_b["category"] == "B"
    assert "TARGET LIKELY PATCHED" in res_b["status"]

    # Case A: Active crash reproduced
    ctx_a = ProgramContext(
        target_path="dummy.c",
        language="c",
        os_platform="linux",
        source_code="",
        active_payloads=[
            CrashPayload(args=["poc.png"], crash_type="Heap Buffer Overflow", exit_code=139)
        ]
    )
    res_a = evaluate_cve_validation_outcome(ctx_a, cve_meta, "1.6.50", is_version_affected=True)
    assert res_a["category"] == "A"
    assert res_a["status"] == "CONFIRMED"

    # Case D: Ungrounded finding
    vuln_ungrounded = VulnerabilityDetail(
        vuln_type="Heap Overflow",
        cwe="CWE-122",
        severity="high",
        line_number=10,
        code_snippet="if (x == 0)",
        verification_status="UNGROUNDED_FINDING",
        verification_annotation="UNGROUNDED FINDING: No memory ops",
        is_false_positive_risk=True
    )
    ctx_d = ProgramContext(
        target_path="dummy.c",
        language="c",
        os_platform="linux",
        source_code="",
        vulnerabilities=[vuln_ungrounded]
    )
    res_d = evaluate_cve_validation_outcome(ctx_d, cve_meta, "1.6.50", is_version_affected=True)
    assert res_d["category"] == "D"
    assert res_d["status"] == "UNGROUNDED"

    # Case C: Pipeline Gap (affected version, but 0 crashes reproduced)
    ctx_c = ProgramContext(
        target_path="dummy.c",
        language="c",
        os_platform="linux",
        source_code="",
        active_payloads=[
            CrashPayload(args=["poc.png"], exit_code=0, stdout="Normal execution", stderr="")
        ]
    )
    res_c = evaluate_cve_validation_outcome(ctx_c, cve_meta, "1.6.50", is_version_affected=True)
    assert res_c["category"] == "C"
    assert "PIPELINE GAP" in res_c["status"]
    assert res_c["diagnostic"]["payloads_tested"] == 1
    # Reachability must not be empty parentheses
    assert res_c["diagnostic"]["reachability_status"] != ""
    assert res_c["diagnostic"]["reachability_message"] != ""


from unittest.mock import patch, MagicMock
from mutagen.executor import execute_payload


def test_docker_infrastructure_error_classified_as_execution_error():
    """
    Simulates Docker CLI returning the exact error:
    'you cannot start and attach multiple containers at once'
    and confirms it is returned as EXECUTION_ERROR, not silently as a clean run.
    """
    with patch("mutagen.executor._check_docker_functional", return_value=True):
        # Mock subprocess.run for create and start
        mock_create = MagicMock()
        mock_create.returncode = 0
        mock_create.stdout = "a1b2c3d4e5f67890\n"

        mock_start = MagicMock()
        mock_start.returncode = 1
        mock_start.stdout = ""
        mock_start.stderr = "you cannot start and attach multiple containers at once\n"

        def mock_subp_run(cmd, *args, **kwargs):
            if "create" in cmd:
                return mock_create
            elif "start" in cmd:
                return mock_start
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=mock_subp_run):
            res = execute_payload(
                exe_path="target_app",
                args=["arg1", "arg2"],
                input_data=None,
                delivery_mode="args",
                timeout=5,
                sandbox="docker"
            )

            assert res["crashed"] is False
            assert res["crash_type"] == "EXECUTION_ERROR"
            assert "you cannot start and attach" in res["stderr"]


@pytest.mark.asyncio
async def test_supervisor_records_execution_error():
    """
    Ensures that when execute_payload returns EXECUTION_ERROR, FuzzingSupervisorAgent
    sets payload.crash_type = 'EXECUTION_ERROR' and does NOT count it as a clean negative.
    """
    from mutagen.agents.supervisor import FuzzingSupervisorAgent
    ctx = ProgramContext(
        target_path="dummy.c",
        language="c",
        os_platform="linux",
        source_code="int main() { return 0; }",
        active_payloads=[CrashPayload(args=["test_input"])]
    )

    with patch("mutagen.agents.supervisor.compile_target", return_value="dummy.exe"):
        with patch("os.path.exists", return_value=True):
            with patch("mutagen.agents.supervisor.execute_payload", return_value={
                "crashed": False,
                "crash_type": "EXECUTION_ERROR",
                "return_code": 1,
                "stdout": "",
                "stderr": "you cannot start and attach multiple containers at once",
                "container_id": "a1b2c3d4e5f6"
            }):
                supervisor = FuzzingSupervisorAgent()
                updated_ctx = await supervisor.process(ctx)
                p0 = updated_ctx.active_payloads[0]
                assert p0.crash_type == "EXECUTION_ERROR"
                assert any("Infrastructure/Execution error" in log for log in updated_ctx.logs)

