import os
import subprocess
import sys

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


def _can_run_docker_sandbox() -> bool:
    """Check if Docker is functional AND able to run Linux containers with the sandbox image."""
    if not _check_docker_functional():
        return False
    if os.name == "nt" or sys.platform == "darwin":
        # Windows/macOS runners cannot run Linux ELF containers natively without VM setup
        return False
    image = os.environ.get("MUTAGEN_SANDBOX_IMAGE", "ubuntu:latest")
    try:
        check = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=5
        )
        return check.returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _can_run_docker_sandbox(), reason="Docker daemon unable to run Linux sandbox image")
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

    if res.get("container_id") == "" and "Docker create failed" in res.get("stderr", ""):
        pytest.skip(f"Docker sandbox environment unable to create container: {res.get('stderr')}")

    assert res.get("container_id") is not None
    container_id = res.get("container_id")
    assert len(container_id) > 0, "Expected non-empty verifiable Container ID"
    assert res.get("container_image") != ""
    assert res.get("container_image_digest") != ""
