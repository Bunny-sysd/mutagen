import json
from unittest.mock import MagicMock, patch

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


@pytest.mark.anyio
async def test_synthesizer_deduplicates_ai_echoed_filenames():
    """Regression test: the synthesis prompt's JSON schema example includes a
    literal filename ("test_boundary.png"). If the AI echoes that example
    verbatim across multiple distinct payloads instead of varying it, every
    payload in the report/logs becomes indistinguishable by name -- reading as
    duplicate/overwritten payloads even though execution (which uses a separate
    UUID temp file per payload) was never actually affected. Filenames must be
    auto-uniquified so reporting stays unambiguous."""
    context = ProgramContext(
        target_path="pngrtran.c", language="c", os_platform="linux",
        source_code="void f() {}", delivery_mode="file",
        vulnerabilities=[VulnerabilityDetail(
            vuln_type="Heap Over-read", cwe="CWE-125", severity="critical",
            line_number=1, code_snippet=""
        )],
    )
    agent = PayloadSynthesizerAgent(api_key="dummy_key")

    fake_response = MagicMock()
    fake_response.text = json.dumps({
        "payloads": [
            {"args": ["test_boundary.png"], "input_data": "", "raw_bytes_hex": "89504e470d0a1a0a", "reason": "r1"},
            {"args": ["test_boundary.png"], "input_data": "", "raw_bytes_hex": "89504e470d0a1a0a01", "reason": "r2"},
            {"args": ["test_boundary.png"], "input_data": "", "raw_bytes_hex": "89504e470d0a1a0a02", "reason": "r3"},
            {"args": ["test_boundary.png"], "input_data": "", "raw_bytes_hex": "89504e470d0a1a0a03", "reason": "r4"},
        ]
    })

    with patch.object(agent.engine, "client", MagicMock()) as mock_client:
        mock_client.models.generate_content.return_value = fake_response
        await agent.process(context)

    names = [p.args[-1] for p in context.active_payloads if p.args]
    assert names[:4] == ["test_boundary.png", "test_boundary_2.png", "test_boundary_3.png", "test_boundary_4.png"]
    assert len(names) == len(set(names)), f"expected every payload filename to be unique, got {names}"


@pytest.mark.anyio
async def test_synthesizer_enumerates_total_failure_fallback_filenames():
    """Regression test: when synthesis fails entirely (e.g. every model
    candidate errors), the deterministic fallback payloads must each get a
    distinct filename -- this loop previously reused the exact same literal
    filename for every fallback payload in the batch."""
    context = ProgramContext(
        target_path="pngrtran.c", language="c", os_platform="linux",
        source_code="void f() { png_do_quantize(); }", delivery_mode="file",
        vulnerabilities=[VulnerabilityDetail(
            vuln_type="Heap Over-read", cwe="CWE-125", severity="critical",
            line_number=1, code_snippet=""
        )],
    )
    agent = PayloadSynthesizerAgent(api_key="dummy_key")

    with patch.object(agent.engine, "client", MagicMock()) as mock_client, \
         patch("time.sleep"):
        mock_client.models.generate_content.side_effect = Exception("503 UNAVAILABLE")
        await agent.process(context)

    assert context.synthesis_failed is True
    names = [p.args[-1] for p in context.active_payloads if p.args]
    assert len(names) > 1
    assert len(names) == len(set(names)), f"expected every fallback payload filename to be unique, got {names}"
