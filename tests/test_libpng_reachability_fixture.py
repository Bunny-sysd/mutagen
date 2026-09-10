import os
from unittest.mock import patch

import pytest

from mutagen.agents.supervisor import FuzzingSupervisorAgent
from mutagen.reachability_checker import select_best_reachable_binary, verify_binary_reachability
from mutagen.state import ProgramContext, VulnerabilityDetail


def test_reachability_checker_libpng_classic_vs_simplified_api(tmp_path):
    """
    Test fixture verifying:
    1. pngtest reaches classic/low-level read path (png_read_IDAT_data / png_read_row).
    2. pngstest reaches only simplified API (png_image_begin_read_from_file) and NOT low-level IDAT path.
    3. Candidate selection selects pngtest over pngstest when targeting low-level read path.
    """
    # Create mock pngtest binary & source with classic read symbols
    pngtest_bin = tmp_path / ("pngtest" if os.name != 'nt' else "pngtest.exe")
    pngtest_src = tmp_path / "pngtest.c"
    pngtest_src.write_text("""
#include "png.h"
int main() {
    png_read_row(NULL, NULL, NULL);
    png_read_IDAT_data(NULL, NULL, 0);
    return 0;
}
""")
    pngtest_bin.write_text("pngtest_binary_image_with_png_read_IDAT_data_and_png_read_row")

    # Create mock pngstest binary & source with simplified read symbols ONLY
    pngstest_bin = tmp_path / ("pngstest" if os.name != 'nt' else "pngstest.exe")
    pngstest_src = tmp_path / "pngstest.c"
    pngstest_src.write_text("""
#include "png.h"
int main() {
    png_image_begin_read_from_file(NULL, "test.png");
    return 0;
}
""")
    pngstest_bin.write_text("pngstest_binary_image_with_png_image_begin_read_from_file_only")

    # 1. Check reachability of classic IDAT read function on pngtest
    res_pngtest = verify_binary_reachability(str(pngtest_bin), "png_read_IDAT_data", str(pngtest_src))
    assert res_pngtest["reachable"] is True
    assert "png_read_IDAT_data" in res_pngtest["reason"]

    # 2. Check reachability of classic IDAT read function on pngstest
    res_pngstest = verify_binary_reachability(str(pngstest_bin), "png_read_IDAT_data", str(pngstest_src))
    assert res_pngstest["reachable"] is False
    assert "absent" in res_pngstest["reason"].lower() or "not" in res_pngstest["reason"].lower()

    # 3. Test selection when both are candidates for low-level vulnerability
    candidates = [str(pngstest_bin), str(pngtest_bin)]
    selected, status = select_best_reachable_binary(candidates, target_hint="pngread.c", vuln_function="png_read_IDAT_data")

    assert selected == str(pngtest_bin)
    assert status["reachable"] is True


def test_reachability_checker_unconfirmed_fallback_message():
    """
    Test fixture verifying that when no candidate binary reaches the vulnerable function,
    select_best_reachable_binary returns None and reports explicit unconfirmed status.
    """
    candidates = ["/mock/build/dummy_bin"]
    selected, status = select_best_reachable_binary(candidates, target_hint="target.c", vuln_function="non_existent_func")

    assert selected is None
    assert status["reachable"] is False
    assert "no build target exercises this code path" in status["reason"]


@pytest.mark.anyio
async def test_supervisor_verifies_cve_affected_function_not_triage_finding():
    """
    Regression test: in Ground-Truth CVE mode, reachability must be verified for
    the CVE's own documented affected function (e.g. png_do_quantize for
    CVE-2025-64505), not whichever function the triage step happened to flag.
    Triage findings can legitimately land in an unrelated function (or drift
    between runs), which previously caused reachability results like "reaches
    png_set_quantize" to be reported for a CVE actually targeting a different
    function entirely.
    """
    ctx = ProgramContext(target_path="dummy.c", language="c", os_platform="win32", source_code="int main(){return 0;}")
    ctx.vulnerabilities.append(VulnerabilityDetail(
        vuln_type="Unrelated Finding", cwe="CWE-125", severity="high", line_number=999, code_snippet=""
    ))
    ctx.cve_meta = {"cve_id": "CVE-2025-64505", "affected_functions": ["png_do_quantize"]}

    agent = FuzzingSupervisorAgent(api_key="k")
    with patch("mutagen.agents.supervisor.compile_target") as mock_compile, \
         patch("mutagen.reachability_checker.verify_binary_reachability") as mock_verify, \
         patch("mutagen.reachability_checker.extract_vulnerable_function_name") as mock_extract, \
         patch("os.path.exists", return_value=True):
        mock_compile.return_value = "pngtest.exe"
        mock_verify.return_value = {"reachable": True, "reason": "Symbol 'png_do_quantize' found"}
        await agent.process(ctx)

        assert mock_compile.call_args.kwargs.get("vuln_function") == "png_do_quantize"
        assert mock_extract.call_count == 0
        assert ctx.reachability_status == "REACHABLE"


@pytest.mark.anyio
async def test_supervisor_falls_back_to_triage_finding_without_cve_metadata():
    """Non-CVE-mode runs must keep deriving the target function from the triage
    finding's enclosing function, unchanged from prior behavior."""
    ctx = ProgramContext(target_path="dummy.c", language="c", os_platform="win32", source_code="int main(){return 0;}")
    ctx.vulnerabilities.append(VulnerabilityDetail(
        vuln_type="X", cwe="CWE-125", severity="high", line_number=42, code_snippet=""
    ))

    agent = FuzzingSupervisorAgent(api_key="k")
    with patch("mutagen.agents.supervisor.compile_target") as mock_compile, \
         patch("mutagen.reachability_checker.verify_binary_reachability") as mock_verify, \
         patch("mutagen.reachability_checker.extract_vulnerable_function_name") as mock_extract, \
         patch("os.path.exists", return_value=True):
        mock_compile.return_value = "a.exe"
        mock_verify.return_value = {"reachable": True, "reason": "ok"}
        mock_extract.return_value = "triage_flagged_func"
        await agent.process(ctx)

        assert mock_extract.call_count == 1
        assert mock_extract.call_args.args == ("dummy.c", 42)
        assert mock_compile.call_args.kwargs.get("vuln_function") == "triage_flagged_func"
