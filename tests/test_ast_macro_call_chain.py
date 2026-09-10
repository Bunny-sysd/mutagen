import os

from mutagen.reachability_checker import (
    get_expanded_reachability_set,
    select_best_reachable_binary,
    verify_binary_reachability,
)


def test_macro_alias_and_call_chain_resolution(tmp_path):
    """
    Tests that get_expanded_reachability_set extracts macro aliases (#define)
    and caller functions, allowing verify_binary_reachability to match candidate targets.
    """
    header_file = tmp_path / "target_lib.h"
    header_file.write_text("""
#ifndef TARGET_LIB_H
#define TARGET_LIB_H

#define public_api_macro(x) internal_vulnerable_func(x)

#endif
""")

    source_file = tmp_path / "target_lib.c"
    source_file.write_text("""
#include "target_lib.h"

void internal_vulnerable_func(int x) {
    // vulnerable code
}

void public_wrapper_func(int x) {
    internal_vulnerable_func(x);
}
""")

    main_app_src = tmp_path / "app_main.c"
    main_app_src.write_text("""
#include "target_lib.h"

int main() {
    public_api_macro(42);
    return 0;
}
""")

    main_app_bin = tmp_path / "app_main.exe" if os.name == 'nt' else tmp_path / "app_main"
    main_app_bin.write_text("binary_image_with_public_api_macro_symbol_and_wrapper")

    # 1. Verify reachability set includes internal_vulnerable_func, public_api_macro, public_wrapper_func
    symbols = get_expanded_reachability_set(str(tmp_path), "internal_vulnerable_func")
    assert "internal_vulnerable_func" in symbols
    assert "public_api_macro" in symbols
    assert "public_wrapper_func" in symbols

    # 2. Verify reachability of candidate binary when target_dir is provided
    res = verify_binary_reachability(str(main_app_bin), "internal_vulnerable_func", candidate_source=str(main_app_src), target_dir=str(tmp_path))
    assert res["reachable"] is True
    assert "public_api_macro" in res["reason"] or "internal_vulnerable_func" in res["reason"]

    # 3. Test select_best_reachable_binary using candidate list
    selected, status = select_best_reachable_binary([str(main_app_bin)], target_hint=str(tmp_path), vuln_function="internal_vulnerable_func")
    assert selected == str(main_app_bin)
    assert status["reachable"] is True


def test_caller_alias_expansion_is_scoped_to_actual_function_body(tmp_path):
    """
    Regression test: a prior line-by-line heuristic (no brace/scope tracking)
    attributed ANY function whose signature-looking line preceded a later
    occurrence of the target symbol's text anywhere in the file -- including in
    a comment, string, or a completely unrelated function -- as a "caller".
    This produced real false positives (e.g. reachability reported an unrelated
    function as reaching the CVE target). The AST-scoped implementation must
    only add a function whose actual body references the symbol.
    """
    source_file = tmp_path / "lib.c"
    source_file.write_text("""
void real_caller(int x) {
    vulnerable_target(x);
}

void unrelated_function(int y) {
    do_something_else(y);
    // Just a comment mentioning vulnerable_target for documentation purposes,
    // this function does not call it.
}
""")

    symbols = get_expanded_reachability_set(str(tmp_path), "vulnerable_target")
    assert "real_caller" in symbols
    assert "unrelated_function" not in symbols
