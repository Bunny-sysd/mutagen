import json
from unittest.mock import MagicMock, patch

from mutagen.engines.claude import ClaudeEngine


@patch("anthropic.Anthropic")
def test_claude_engine_analyze_code(mock_anthropic_class):
    mock_client = MagicMock()
    mock_anthropic_class.return_value = mock_client

    from mutagen.models import FuzzPayload, FuzzPayloadList
    mock_parsed = FuzzPayloadList(
        payloads=[
            FuzzPayload(
                args=["claude_payload"],
                input_data="",
                vuln_type="buffer_overflow",
                reason="strcpy",
                severity="critical",
                cwe="CWE-120"
            )
        ]
    )

    mock_message = MagicMock()
    mock_message.parsed = mock_parsed
    mock_client.beta.messages.parse.return_value = mock_message

    engine = ClaudeEngine(api_key="test_claude_key")
    payloads = engine.analyze_code("int main() { return 0; }", 5, "args", False)

    assert len(payloads) == 1
    assert payloads[0]["vuln_type"] == "buffer_overflow"
    assert payloads[0]["args"] == ["claude_payload"]

    mock_client.beta.messages.parse.assert_called_once()
    called_kwargs = mock_client.beta.messages.parse.call_args[1]
    from mutagen.constants import DEFAULT_CLAUDE_FALLBACK_MODELS
    assert called_kwargs["model"] in DEFAULT_CLAUDE_FALLBACK_MODELS
    assert called_kwargs["response_model"] == FuzzPayloadList
    assert called_kwargs["system"] == "You are an automated code audit assistant."


@patch("anthropic.Anthropic")
def test_claude_engine_refine_payload(mock_anthropic_class):
    mock_client = MagicMock()
    mock_anthropic_class.return_value = mock_client

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=json.dumps([
        {
            "args": ["refined_claude"],
            "input_data": "",
            "vuln_type": "buffer_overflow",
            "reason": "bypass",
            "severity": "critical",
            "cwe": "CWE-120"
        }
    ]))]
    mock_client.messages.create.return_value = mock_message

    engine = ClaudeEngine(api_key="test_claude_key")
    payloads = engine.refine_payload(
        source_code="int main() { return 0; }",
        failed_args=["failed1"],
        failed_input="",
        stdout="ok",
        stderr="",
        return_code=0,
        delivery_mode="args"
    )

    assert len(payloads) == 1
    assert payloads[0]["args"] == ["refined_claude"]

@patch("anthropic.Anthropic")
def test_claude_engine_generate_patch_and_exploit(mock_anthropic_class):
    mock_client = MagicMock()
    mock_anthropic_class.return_value = mock_client

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="```c\npatched_c_code_claude\n```")]
    mock_client.messages.create.return_value = mock_message

    engine = ClaudeEngine(api_key="test_claude_key")
    patch_code = engine.generate_patch("source", {"vuln_type": "test"})
    assert patch_code == "patched_c_code_claude"

    mock_message.content = [MagicMock(text="```c\nrefined_c_code_claude\n```")]
    refined_patch = engine.refine_patch("source", "bad_patch", "compiler error", {"vuln_type": "test"})
    assert refined_patch == "refined_c_code_claude"

    mock_message.content = [MagicMock(text="```python\nexploit_python_code_claude\n```")]
    exploit_code = engine.generate_exploit("source", {"args": ["x"]}, "exe_path", "args")
    assert exploit_code == "exploit_python_code_claude"


@patch("anthropic.Anthropic")
def test_claude_engine_generate_payloads_unparseable_prose_fallback(mock_anthropic_class):
    """Stress tests Claude fallback when structured parse fails AND fallback returns malformed prose."""
    mock_client = MagicMock()
    mock_anthropic_class.return_value = mock_client

    # 1. Beta parse fails on all models
    mock_client.beta.messages.parse.side_effect = Exception("400 Structured outputs unsupported on this model")

    # 2. Raw generate returns non-JSON conversational prose with no markdown fences
    mock_prose_msg = MagicMock()
    mock_prose_msg.content = [MagicMock(text="I analyzed your code thoroughly. However, no memory safety vulnerabilities were detected in main().")]
    mock_client.messages.create.return_value = mock_prose_msg

    engine = ClaudeEngine(api_key="test_claude_key")
    payloads = engine.generate_payloads("int main() { return 0; }", "Generate fuzzing payloads", max_payloads=5)

    # Must return empty list, not crash or raise an unhandled exception
    assert payloads == []

    # 3. Verify degradation in synthesizer agent
    from mutagen.agents.synthesizer import PayloadSynthesizerAgent
    from mutagen.cve_validator import evaluate_cve_validation_outcome
    from mutagen.state import ProgramContext, VulnerabilityDetail

    context = ProgramContext(
        target_path="targets/test_target.c",
        language="c",
        os_platform="linux",
        source_code="int main() { return 0; }",
        vulnerabilities=[VulnerabilityDetail(vuln_type="buffer_overflow", cwe="CWE-120", function="main", severity="high", line_number=1, code_snippet="char buf[64];")],
        validate_cve="CVE-2025-64505",
    )

    agent = PayloadSynthesizerAgent(model_provider="claude", api_key="test_claude_key")
    import asyncio
    context = asyncio.run(agent.process(context))

    # Synthesis failed must be explicitly set to True
    assert context.synthesis_failed is True
    # Fallback seed payloads must be inserted into active_payloads
    assert len(context.active_payloads) > 0
    assert all(p.is_fallback for p in context.active_payloads)

    # 4. In CVE validator, must produce Category F (INCONCLUSIVE — SYNTHESIS FAILED)
    outcome = evaluate_cve_validation_outcome(
        context=context,
        cve_meta={"cve_id": "CVE-2025-64505", "fixed_version": "1.6.51"},
        detected_version="1.6.50",
        is_version_affected=True,
    )
    assert outcome["category"] == "F"
    assert "SYNTHESIS FAILED" in outcome["status"]


@patch("anthropic.Anthropic")
def test_claude_engine_extended_thinking_omits_temperature(mock_anthropic_class):
    """Asserts that when extended thinking is enabled, temperature is omitted from API call kwargs."""
    mock_client = MagicMock()
    mock_anthropic_class.return_value = mock_client

    mock_msg = MagicMock()
    mock_msg.content = [MagicMock(text="response text")]
    mock_client.messages.create.return_value = mock_msg

    engine = ClaudeEngine(api_key="test_claude_key")
    engine.thinking_enabled = True

    # Test _generate
    res = engine._generate("Test prompt with thinking")
    assert res == "response text"
    mock_client.messages.create.assert_called_once()
    called_kwargs = mock_client.messages.create.call_args[1]
    assert "temperature" not in called_kwargs

    # Test _parse_generate
    from mutagen.models import FuzzSequenceList
    mock_parsed_msg = MagicMock()
    mock_parsed_msg.parsed = FuzzSequenceList(sequences=[])
    mock_client.beta.messages.parse.return_value = mock_parsed_msg

    engine._parse_generate("Test prompt with thinking", FuzzSequenceList, "sequences")
    mock_client.beta.messages.parse.assert_called_once()
    parse_kwargs = mock_client.beta.messages.parse.call_args[1]
    assert "temperature" not in parse_kwargs


