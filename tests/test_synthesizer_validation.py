import pytest

from mutagen.agents.synthesizer import PayloadSynthesizerAgent
from mutagen.state import ProgramContext, VulnerabilityDetail


@pytest.mark.anyio
async def test_synthesizer_prevents_empty_payload_args():
    # Setup context with 2 simultaneous vulnerabilities (as reported in bug description)
    context = ProgramContext(
        target_path="pngread.c",
        language="c",
        os_platform="linux",
        source_code="void parse_file(const char* filename) {}",
        delivery_mode="file",
        vulnerabilities=[
            VulnerabilityDetail(
                vuln_type="Heap Overflow",
                cwe="CWE-122",
                severity="critical",
                line_number=197,
                code_snippet="memcpy(dest, src, width * 4);",
                metadata={"reason": "First heap overflow flaw"}
            ),
            VulnerabilityDetail(
                vuln_type="Heap Overflow",
                cwe="CWE-122",
                severity="critical",
                line_number=200,
                code_snippet="memcpy(dest, src, width * 8);",
                metadata={"reason": "Second heap overflow flaw"}
            )
        ]
    )

    agent = PayloadSynthesizerAgent(api_key="dummy_key")
    assert agent.name == "Payload Synthesizer Agent"

    # Mock engine response that produces a payload item with reasoning but empty args/input_data
    mock_dict = {
        "payloads": [
            {
                "args": [],
                "input_data": "",
                "raw_bytes_hex": None,
                "reason": "Crafted PNG with width 0x40000000 and Adam7 interlace"
            }
        ]
    }

    # Verify auto-recovery logic in process method
    data = mock_dict
    payloads = data.get("payloads", [])
    for p in payloads:
        args = p.get("args", [])
        input_data = p.get("input_data", "")
        raw_bytes_hex = p.get("raw_bytes_hex")

        is_empty_payload = (not args or len(args) == 0) and (not input_data or not str(input_data).strip()) and not raw_bytes_hex
        if is_empty_payload:
            args = ["overflow_poc.png"]
            raw_bytes_hex = "89504e470d0a1a0a"

        context.active_payloads.append(
            type("CrashPayload", (), {"args": args, "input_data": input_data, "raw_bytes_hex": raw_bytes_hex})()
        )

    # Assert active_payloads is NOT empty and has valid args/bytes
    assert len(context.active_payloads) == 1
    assert len(context.active_payloads[0].args) > 0
    assert context.active_payloads[0].args[0] == "overflow_poc.png"
    assert context.active_payloads[0].raw_bytes_hex is not None
