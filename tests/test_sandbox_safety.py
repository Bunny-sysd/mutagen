import os
from unittest.mock import patch

import pytest

from mutagen.reporter import save_crash_report


def test_safety_gate_aborts_in_ci_mode_when_docker_unavailable():
    from mutagen.orchestrator import AgentOrchestrator

    with patch("mutagen.orchestrator.TriageAgent"), \
         patch("mutagen.orchestrator.PayloadSynthesizerAgent"), \
         patch("mutagen.orchestrator.FuzzingSupervisorAgent"), \
         patch("mutagen.orchestrator.PatchEngineerAgent"), \
         patch("mutagen.orchestrator.StructuralValidatorAgent"):

        orchestrator = AgentOrchestrator(
            target_path="targets/dummy.c",
            source_code="int main(){return 0;}"
        )

        with patch("mutagen.executor._check_docker_functional", return_value=False):
            with pytest.raises(SystemExit) as exc_info:
                orchestrator.gate_docker_sandbox_safety(ci_mode=True)
            assert exc_info.value.code == 1
            assert any("ABORTED: Docker unavailable in non-interactive/CI mode" in log for log in orchestrator.context.logs)


def test_safety_gate_interactive_prompt_proceeds_on_user_confirmation():
    from mutagen.orchestrator import AgentOrchestrator

    with patch("mutagen.orchestrator.TriageAgent"), \
         patch("mutagen.orchestrator.PayloadSynthesizerAgent"), \
         patch("mutagen.orchestrator.FuzzingSupervisorAgent"), \
         patch("mutagen.orchestrator.PatchEngineerAgent"), \
         patch("mutagen.orchestrator.StructuralValidatorAgent"):

        orchestrator = AgentOrchestrator(
            target_path="targets/dummy.c",
            source_code="int main(){return 0;}"
        )

        with patch("mutagen.executor._check_docker_functional", return_value=False):
            with patch("sys.stdin.isatty", return_value=True):
                with patch("builtins.input", return_value="1"):
                    orchestrator.gate_docker_sandbox_safety(ci_mode=False)
                    assert orchestrator.context.docker_available is False
                    assert orchestrator.context.sandboxed is False
                    assert orchestrator.context.user_confirmed_unsandboxed is True


def test_safety_gate_interactive_prompt_aborts_on_user_decline():
    from mutagen.orchestrator import AgentOrchestrator

    with patch("mutagen.orchestrator.TriageAgent"), \
         patch("mutagen.orchestrator.PayloadSynthesizerAgent"), \
         patch("mutagen.orchestrator.FuzzingSupervisorAgent"), \
         patch("mutagen.orchestrator.PatchEngineerAgent"), \
         patch("mutagen.orchestrator.StructuralValidatorAgent"):

        orchestrator = AgentOrchestrator(
            target_path="targets/dummy.c",
            source_code="int main(){return 0;}"
        )

        with patch("mutagen.executor._check_docker_functional", return_value=False):
            with patch("sys.stdin.isatty", return_value=True):
                with patch("builtins.input", return_value="2"):
                    with pytest.raises(SystemExit) as exc_info:
                        orchestrator.gate_docker_sandbox_safety(ci_mode=False)
                    assert exc_info.value.code == 1


def test_crash_report_contains_sandboxed_metadata(tmp_path):
    crashes = [{
        "args": ["overflow.png"],
        "input_data": "A" * 64,
        "vuln_type": "Memory Corruption",
        "return_code": -11,
        "cwe": "CWE-120"
    }]

    # Run save_crash_report in real temp directory
    orig_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        json_path, html_path = save_crash_report(
            crashes=crashes,
            target_name="test_target",
            total_tested=1,
            sandboxed=True,
            user_confirmed_unsandboxed=False,
            docker_available=True
        )
        assert os.path.exists(json_path)
        assert os.path.exists(html_path)

        import json
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
            assert data["sandboxed"] is True
            assert data["user_confirmed_unsandboxed"] is False
            assert data["docker_available"] is True
    finally:
        os.chdir(orig_cwd)


def test_ci_mode_aborts_even_with_allow_unsandboxed_env_var():
    """Asserts that orchestrator strictly aborts in CI mode even if MUTAGEN_ALLOW_UNSANDBOXED=1 is set."""
    from mutagen.orchestrator import AgentOrchestrator

    with patch.dict(os.environ, {"CI": "1", "MUTAGEN_ALLOW_UNSANDBOXED": "1"}):
        with patch("mutagen.orchestrator.TriageAgent"), \
             patch("mutagen.orchestrator.PayloadSynthesizerAgent"), \
             patch("mutagen.orchestrator.FuzzingSupervisorAgent"), \
             patch("mutagen.orchestrator.PatchEngineerAgent"), \
             patch("mutagen.orchestrator.StructuralValidatorAgent"):
            orchestrator = AgentOrchestrator(
                target_path="targets/dummy.c",
                source_code="int main(){return 0;}",
                api_key="test_api_key"
            )

            with patch("mutagen.executor._check_docker_functional", return_value=False):
                with pytest.raises(SystemExit) as exc_info:
                    orchestrator.gate_docker_sandbox_safety(ci_mode=True)
                assert exc_info.value.code == 1
                assert any("ABORTED: Docker unavailable in non-interactive/CI mode" in log for log in orchestrator.context.logs)


def test_executor_aborts_in_ci_mode_even_with_allow_unsandboxed_env_var():
    """Asserts that execute_payload strictly aborts in CI mode when Docker is unavailable even if MUTAGEN_ALLOW_UNSANDBOXED=1 is set."""
    from mutagen.executor import execute_payload

    with patch.dict(os.environ, {"CI": "1", "MUTAGEN_ALLOW_UNSANDBOXED": "1"}):
        with patch("mutagen.executor._check_docker_functional", return_value=False):
            with pytest.raises(SystemExit) as exc_info:
                execute_payload("dummy_exe", ["arg1"], "", "args", 5, sandbox="docker")
            assert exc_info.value.code == 1

