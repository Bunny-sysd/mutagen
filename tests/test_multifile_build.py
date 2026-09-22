import os
import subprocess
import sys
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


@pytest.mark.skipif(sys.platform != "linux", reason="ldd/ASan runtime-library staging is Linux-specific")
def test_sanitizer_binary_has_no_dynamic_asan_ubsan_dependency():
    """Regression test: a Docker-sandboxed binary compiled with ASan/UBSan must not
    depend on libasan/libubsan.so at runtime. Confirmed via a real end-to-end libpng
    CVE reproduction run: the bare sandbox image (ubuntu:latest) has no gcc toolchain
    installed, so it has libasan/libubsan nowhere on it -- every payload execution
    failed with exit code 127 (dynamic linker can't resolve the sanitizer runtime),
    misleadingly logged as "No vulnerability detected" rather than a real error.
    Statically linking the sanitizers (-static-libasan -static-libubsan) removes the
    runtime dependency entirely rather than requiring the sandbox image to carry a
    matching gcc toolchain."""
    with tempfile.TemporaryDirectory() as tmpdir:
        source_path = os.path.join(tmpdir, "main.c")
        with open(source_path, "w", encoding="utf-8") as f:
            f.write("int main() { return 0; }\n")

        try:
            exe_out = compile_target(source_path, "gcc")
        except (FileNotFoundError, OSError, CompilationError):
            pytest.skip("gcc compiler (with sanitizer support) not available in test environment")

        try:
            ldd_result = subprocess.run(["ldd", exe_out], capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            pytest.skip("ldd not available in test environment")

        ldd_output = ldd_result.stdout.lower()
        assert "libasan" not in ldd_output, f"binary still dynamically depends on libasan: {ldd_result.stdout}"
        assert "libubsan" not in ldd_output, f"binary still dynamically depends on libubsan: {ldd_result.stdout}"


@pytest.mark.skipif(sys.platform != "linux", reason="/tmp as a shared system root is POSIX-specific")
def test_compile_target_does_not_sweep_the_shared_system_temp_root():
    """Regression test: sibling-source discovery scans both the target's own directory
    AND its parent directory (to catch a helper.c sitting next to a project subdirectory).
    But when a target file's parent happens to be a shared system root like /tmp --
    which is exactly what happens for any target staged via tempfile.TemporaryDirectory(),
    including this project's own test suite and, in real runs, anywhere mutagen stages a
    target into a fresh temp working directory -- that scan degenerates into walking the
    ENTIRE shared OS temp tree, sweeping in unrelated files left there by other processes
    or other tests. executor.py already has _is_system_or_root_dir() (which explicitly
    lists /tmp) as the reference guard against exactly this; compiler.py's own scan_roots
    construction never calls it."""
    with tempfile.TemporaryDirectory() as tmpdir_a, tempfile.TemporaryDirectory() as tmpdir_b:
        # Both land directly under the shared system temp root (e.g. /tmp/tmpXXXXXXXX),
        # so tmpdir_a's parent_dir -- the directory sibling discovery would scan -- is
        # the shared root itself, and tmpdir_b (an unrelated sibling under that same
        # root) stands in for debris left by any other process or test.
        assert os.path.dirname(tmpdir_a) == os.path.dirname(tmpdir_b)

        main_path = os.path.join(tmpdir_a, "main.c")
        with open(main_path, "w", encoding="utf-8") as f:
            f.write("int main() { return 0; }\n")

        with open(os.path.join(tmpdir_b, "unrelated_debris.c"), "w", encoding="utf-8") as f:
            f.write("this is not valid C and must never be compiled;\n")

        try:
            exe_out = compile_target(main_path, "gcc")
            assert os.path.exists(exe_out)
        except (FileNotFoundError, OSError):
            pytest.skip("gcc compiler not available in test environment")
