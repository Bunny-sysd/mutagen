from mutagen.editor import VirtualCodeEditor

SAMPLE_C_FILE = """#include <stdio.h>
#include <string.h>

void helper_func(void) {
    printf("helper\\n");
}

void vulnerable_quantize(char *input) {
    char buffer[16];
    strcpy(buffer, input);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_quantize(argv[1]);
    }
    return 0;
}
"""


def test_virtual_editor_open_function_scope():
    editor = VirtualCodeEditor(SAMPLE_C_FILE, language="c", filename="test.c")
    scope = editor.open_vulnerable_scope(target_line=9)

    assert scope is not None
    assert scope.name == "vulnerable_quantize"
    assert scope.scope_type == "function"
    assert "strcpy(buffer, input);" in scope.body
    assert scope.start_line == 8
    assert scope.end_line == 11


def test_virtual_editor_patch_candidate_and_diff():
    editor = VirtualCodeEditor(SAMPLE_C_FILE, language="c", filename="test.c")
    editor.open_vulnerable_scope(target_line=9)

    patched_func = """void vulnerable_quantize(char *input) {
    char buffer[16];
    if (strlen(input) < sizeof(buffer)) {
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\\0';
    }
}"""

    success = editor.apply_patch_candidate(patched_func)
    assert success is True

    # Pre-flight check
    is_valid, msg = editor.run_pre_flight_check()
    assert is_valid is True

    # Check spliced code
    full_code = editor.get_full_patched_code()
    assert "strncpy(buffer, input, sizeof(buffer) - 1);" in full_code
    assert "void helper_func(void)" in full_code
    assert "int main(int argc, char **argv)" in full_code

    # Check diff
    diff = editor.get_unified_diff()
    assert "--- a/test.c" in diff
    assert "+++ b/test.c" in diff
    assert "+    if (strlen(input) < sizeof(buffer)) {" in diff


def test_virtual_editor_search_replace_and_rollback():
    editor = VirtualCodeEditor(SAMPLE_C_FILE, language="c", filename="test.c")
    editor.open_vulnerable_scope(target_line=9)

    # Search and replace
    sr_success = editor.apply_search_replace(
        search_block="strcpy(buffer, input);",
        replace_block="strncpy(buffer, input, 15); buffer[15] = '\\0';"
    )
    assert sr_success is True
    assert "strncpy(buffer, input, 15);" in editor.active_scope.body

    # Rollback
    editor.rollback()
    assert "strcpy(buffer, input);" in editor.active_scope.body


def test_virtual_editor_large_file_splicing():
    # Construct a 1,000-line synthetic C file
    lines = [f"int dummy_func_{i}(void) {{ return {i}; }}" for i in range(1, 500)]
    lines.append("void target_vuln(int *ptr) { *ptr = 42; }")
    lines.extend([f"int dummy_func_{i}(void) {{ return {i}; }}" for i in range(500, 1000)])
    large_source = "\n".join(lines)

    editor = VirtualCodeEditor(large_source, language="c", filename="huge.c")
    scope = editor.open_vulnerable_scope(target_line=500)

    assert scope is not None
    assert scope.name == "target_vuln"

    editor.apply_patch_candidate("void target_vuln(int *ptr) { if (ptr) *ptr = 42; }")
    full_spliced = editor.get_full_patched_code()

    assert "if (ptr) *ptr = 42;" in full_spliced
    assert "int dummy_func_1(void)" in full_spliced
    assert "int dummy_func_999(void)" in full_spliced
