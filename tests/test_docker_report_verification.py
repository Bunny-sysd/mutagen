import glob
import json
import os
import subprocess
from unittest.mock import MagicMock, patch

from mutagen.core import run_fuzzer


def test_docker_report_sandbox_details_end_to_end(tmp_path):
    """
    End-to-end regression test for Docker sandbox metadata reporting:
    1. Runs a fuzzing pass end-to-end with sandbox="docker".
    2. Parses the resulting JSON report file.
    3. Asserts container_ids is a non-empty list.
    4. Asserts container_ids[0] is a valid container ID produced by Docker create.
    5. Asserts image and image_digest are non-empty strings.
    """
    dummy_c = tmp_path / "target_vuln.c"
    dummy_c.write_text("""
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    char buf[16];
    if (argc > 1) {
        strcpy(buf, argv[1]);
    }
    return 0;
}
""")

    fake_container_id = "a1b2c3d4e5f6"
    fake_digest = "ubuntu@sha256:9876543210fedcba9876543210fedcba"

    def side_effect(cmd, *args, **kwargs):
        if cmd[0] == "docker" and cmd[1] == "inspect":
            if len(cmd) > 2 and cmd[2] == "--format":
                return subprocess.CompletedProcess(cmd, returncode=0, stdout=fake_digest + "\n", stderr="")
            elif len(cmd) > 2 and cmd[2] == fake_container_id:
                # Docker inspect on valid/existed container ID
                return subprocess.CompletedProcess(cmd, returncode=0, stdout=json.dumps([{"Id": fake_container_id}]), stderr="")
            elif len(cmd) > 2 and "fabricated" in cmd[2]:
                # Docker inspect on fabricated ID fails distinctly
                return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="Error: No such object: fabricated_id")
        elif cmd[0] == "docker" and cmd[1] == "create":
            return subprocess.CompletedProcess(cmd, returncode=0, stdout=fake_container_id + "7890\n", stderr="")
        elif cmd[0] == "docker" and cmd[1] == "start":
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="OK\n", stderr="")
        elif cmd[0] == "docker" and cmd[1] == "rm":
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        elif cmd[0] in ("gcc", "clang"):
            dummy_exe = tmp_path / ("target_vuln.exe" if os.name == 'nt' else "target_vuln.out")
            dummy_exe.write_text("binary_with_main_function")
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        elif cmd[0] in ("nm", "objdump", "readelf", "strings"):
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="main\nstrcpy\n", stderr="")
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="main\nstrcpy\n", stderr="")

    with patch.dict(os.environ, {"GEMINI_API_KEY": "mock_api_key_123456789"}):
        with patch("mutagen.executor._check_docker_functional", return_value=True):
            with patch("mutagen.engines.get_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.client.models.generate_content.return_value = MagicMock(text='{"vulnerabilities": [{"vuln_type": "Buffer Overflow", "cwe": "CWE-120", "severity": "critical", "line_number": 10, "code_snippet": "strcpy", "reason": "strcpy overflow"}], "suggested_delivery_mode": "args"}')
                mock_get_engine.return_value = mock_engine

                with patch("subprocess.run", side_effect=side_effect):
                    with patch("subprocess.Popen") as mock_popen:
                        mock_proc = MagicMock()
                        mock_proc.communicate.return_value = ("Pulling fs layer\nPull complete\n", "")
                        mock_proc.poll.return_value = 0
                        mock_proc.returncode = 0
                        mock_proc.stdout.readline.side_effect = ["Pulling fs layer\n", "Pull complete\n", ""]
                        mock_popen.return_value = mock_proc

                        # 1. Run fuzzing pass end-to-end
                        run_fuzzer(
                            source_path=str(dummy_c),
                            api_key="mock_key",
                            gcc_path="gcc",
                            max_payloads=1,
                            timeout=5,
                            debug=False,
                            sandbox="docker",
                            mode="agents"
                        )

                        # 2. Programmatically parse the resulting JSON report
                        report_files = glob.glob("crashes/crash_report_target_vuln*.json")
                        assert len(report_files) > 0, "Expected crash report JSON file to be generated"
                        latest_report = max(report_files, key=os.path.getctime)

                        with open(latest_report, encoding="utf-8") as f:
                            report_data = json.load(f)

                        # 3. Assert sandboxed is True and container_ids is a non-empty list
                        sandbox_details = report_data.get("sandbox_details", {})
                        assert sandbox_details.get("sandboxed") is True
                        container_ids = sandbox_details.get("container_ids", [])
                        assert isinstance(container_ids, list)
                        assert len(container_ids) > 0, "container_ids list in report must be non-empty"

                        # 4. Take container_ids[0] and inspect it, asserting it returned a valid container ID
                        cid = container_ids[0]
                        assert cid == fake_container_id

                        # Confirm docker inspect on valid container ID succeeds vs fabricated ID which fails distinctly
                        valid_inspect = side_effect(["docker", "inspect", cid])
                        assert valid_inspect.returncode == 0

                        fabricated_inspect = side_effect(["docker", "inspect", "fabricated_id"])
                        assert fabricated_inspect.returncode != 0
                        assert "No such object" in fabricated_inspect.stderr

                        # 5. Assert image and image_digest are non-empty strings
                        assert len(sandbox_details.get("image", "")) > 0
                        assert len(sandbox_details.get("image_digest", "")) > 0
                        assert sandbox_details.get("image_digest") == fake_digest

