from mutagen.agents.synthesizer import robust_json_parse


def test_robust_json_parsing_malformed_llm_response():
    # Test stripping markdown and raw unescaped newlines/quotes
    malformed = """```json
    {
        "payloads": [
            {
                "args": ["test"],
                "input_data": "raw input",
                "reason": "malformed test"
            }
        ]
    }
    ```"""

    parsed = robust_json_parse(malformed)
    assert "payloads" in parsed
    assert len(parsed["payloads"]) == 1
    assert parsed["payloads"][0]["reason"] == "malformed test"

def test_robust_json_parsing_fallback():
    broken = "This is not json at all!"
    fallback = robust_json_parse(broken)
    assert "payloads" in fallback
    assert "Fallback due to JSON parse error" in fallback["payloads"][0]["reason"]
