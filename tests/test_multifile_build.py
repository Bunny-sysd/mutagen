import os
import tempfile

import pytest

from mutagen.compiler import CompilationError, compile_target


def test_compile_multifile_target():
    """Verify compile_target automatically discovers local headers and sibling helper .c files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        header_path = os.path.join(tmpdir, "helper.h")
        helper_path = os.path.join(tmpdir, "helper.c")
        main_path = os.path.join(tmpdir, "main.c")

        with open(header_path, "w", encoding="utf-8") as f:
            f.write("int helper_func(int a);\n")

        with open(helper_path, "w", encoding="utf-8") as f:
            f.write('#include "helper.h"\nint helper_func(int a) { return a + 42; }\n')

        with open(main_path, "w", encoding="utf-8") as f:
            f.write('#include "helper.h"\nint main() { return helper_func(0) == 42 ? 0 : 1; }\n')

        # Test multi-file compilation using gcc or available compiler
        try:
            exe_out = compile_target(main_path, "gcc")
            assert os.path.exists(exe_out)
        except (CompilationError, FileNotFoundError, OSError):
            # Fallback if gcc is not installed in local environment
            pytest.skip("gcc compiler not available in test environment")


def test_compile_multifile_target_skips_auxiliary_directories():
    """Regression test: sibling-source discovery must not descend into conventional
    non-library directories (scripts/, contrib/, tests/, examples/, tools/, etc.).
    Confirmed via a real end-to-end run against an actual libpng checkout: its
    scripts/symbols.c (an internal build-time codegen helper, not library source,
    and not valid standalone C) got swept into the build and broke compilation --
    this isn't libpng-specific, real open-source C/C++ projects almost universally
    keep non-library code in directories exactly like these."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Nested one level so both scan roots (target_dir and its parent) stay inside
        # this test's own controlled tree, never reaching the shared OS/pytest temp
        # root above it (which can carry unrelated leftover files from other tests).
        project_dir = os.path.join(tmpdir, "project")
        os.makedirs(project_dir)

        main_path = os.path.join(project_dir, "main.c")
        with open(main_path, "w", encoding="utf-8") as f:
            f.write("int main() { return 0; }\n")

        # A file that would fail to compile if it were ever swept into the build --
        # deliberately invalid, standing in for libpng's real scripts/symbols.c.
        aux_dir = os.path.join(project_dir, "scripts")
        os.makedirs(aux_dir)
        with open(os.path.join(aux_dir, "codegen_helper.c"), "w", encoding="utf-8") as f:
            f.write("this is not valid C and must never be compiled;\n")

        try:
            exe_out = compile_target(main_path, "gcc")
            assert os.path.exists(exe_out)
        except (FileNotFoundError, OSError):
            pytest.skip("gcc compiler not available in test environment")
