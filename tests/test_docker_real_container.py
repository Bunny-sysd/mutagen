import os
import subprocess

import pytest

from mutagen.dependency_resolver import _select_best_binary
from mutagen.executor import _check_docker_functional, execute_payload


def test_binary_selection_prioritizes_target_hint():
    candidates = [
        "/build/pngvalid.exe" if os.name == 'nt' else "/build/pngvalid",
        "/build/pngtest.exe" if os.name == 'nt' else "/build/pngtest",
        "/build/pngimage.exe" if os.name == 'nt' else "/build/pngimage",
    ]

    best = _select_best_binary(candidates, target_hint="pngtest.c")
    assert "pngtest" in best
    assert "pngvalid" not in best


def test_binary_selection_deprioritizes_valid_when_test_present():
    candidates = [
        "/build/pngvalid",
        "/build/pngtest",
    ]

    best = _select_best_binary(candidates, target_hint="")
    assert "pngtest" in best


@pytest.mark.skipif(not _check_docker_functional(), reason="Docker daemon not responsive")
def test_real_docker_container_execution_and_id_verification(tmp_path):
    # Compile a simple C binary in temp directory
    dummy_c = tmp_path / "hello.c"
    dummy_c.write_text('#include <stdio.h>\nint main(int argc, char** argv) { printf("HELLO_SANDBOX\\n"); return 0; }\n')

    dummy_exe = tmp_path / ("hello.exe" if os.name == 'nt' else "hello.out")
    res_comp = subprocess.run(["gcc", str(dummy_c), "-o", str(dummy_exe)], capture_output=True, text=True)
    if res_comp.returncode != 0:
        pytest.skip("GCC compiler unavailable for test compilation")

    res = execute_payload(
        exe_path=str(dummy_exe),
        args=[],
        input_data="",
        delivery_mode="args",
        timeout=10,
        sandbox="docker"
    )

    assert res.get("container_id") is not None
    container_id = res.get("container_id")
    assert len(container_id) > 0, "Expected non-empty verifiable Container ID"
    assert res.get("container_image") != ""
    assert res.get("container_image_digest") != ""
