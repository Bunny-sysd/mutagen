import os

from mutagen.reachability_checker import select_best_reachable_binary, verify_binary_reachability


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
