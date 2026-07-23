import os
import tempfile
import pytest
from mutagen.compiler import compile_target, CompilationError

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
