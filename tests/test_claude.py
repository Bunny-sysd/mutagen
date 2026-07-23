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
    assert called_kwargs["model"] == "claude-3-5-sonnet-latest"
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
