import os

from mutagen.dependency_resolver import _select_best_binary


def test_select_best_binary_ignores_cmake_files_internal_artifacts():
    candidates = [
        "c:/project/build/CMakeFiles/3.28.3/CompilerIdC/a.out",
        "c:/project/build/CMakeFiles/3.28.3/CompilerIdCXX/a.out",
        "c:/project/build/libpng_test",
        "c:/project/build/pngvalid",
    ]

    best = _select_best_binary(candidates, target_hint="pngread.c")
    assert best == "c:/project/build/libpng_test"
    assert "CMakeFiles" not in best
    assert "a.out" not in best

def test_build_with_native_tool_cmake_ignores_cmakemodule_dirs(tmp_path):
    build_dir = tmp_path / "build"
    compiler_id_dir = build_dir / "CMakeFiles" / "3.28.3" / "CompilerIdC"
    compiler_id_dir.mkdir(parents=True, exist_ok=True)

    probe_bin = compiler_id_dir / ("a.out" if os.name != 'nt' else "CompilerIdC.exe")
    probe_bin.write_text("probe")

    real_bin = build_dir / ("target_app" if os.name != 'nt' else "target_app.exe")
    real_bin.write_text("binary")

    candidates = [str(probe_bin), str(real_bin)]
    selected = _select_best_binary(candidates, target_hint="main.c")
    assert selected == str(real_bin)
