import json
import pytest
from unittest.mock import MagicMock, patch

from mutagen.engines.gemini import GeminiEngine
from mutagen.engines.openai_engine import OpenAIEngine
from mutagen.engines.ollama import OllamaEngine

# --- GEMINI ENGINE TESTS ----------------------------------------------------

@patch("google.genai.Client")
def test_gemini_engine_analyze_code(mock_client_class):
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    
    mock_response = MagicMock()
    mock_response.text = json.dumps([
        {
            "args": ["payload1"],
            "input_data": "",
            "vuln_type": "buffer_overflow",
            "reason": "strcpy",
            "severity": "critical",
            "cwe": "CWE-120"
        }
    ])
    mock_client.models.generate_content.return_value = mock_response

    engine = GeminiEngine(api_key="test_gemini_key")
    payloads = engine.analyze_code("int main() { return 0; }", 5, "args", False)

    assert len(payloads) == 1
    assert payloads[0]["vuln_type"] == "buffer_overflow"
    assert payloads[0]["args"] == ["payload1"]
    
    # Verify client generate_content call
    mock_client.models.generate_content.assert_called()
    called_args, called_kwargs = mock_client.models.generate_content.call_args
    assert called_kwargs["model"] == "gemini-2.5-flash-lite"
    assert called_kwargs["config"]["response_mime_type"] == "application/json"


@patch("google.genai.Client")
def test_gemini_engine_refine_payload(mock_client_class):
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    
    mock_response = MagicMock()
    mock_response.text = json.dumps([
        {
            "args": ["payload_refined"],
            "input_data": "",
            "vuln_type": "buffer_overflow",
            "reason": "bypass",
            "severity": "critical",
            "cwe": "CWE-120"
        }
    ])
    mock_client.models.generate_content.return_value = mock_response

    engine = GeminiEngine(api_key="test_gemini_key")
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
    assert payloads[0]["args"] == ["payload_refined"]


@patch("google.genai.Client")
def test_gemini_engine_generate_patch_and_exploit(mock_client_class):
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    
    mock_response = MagicMock()
    mock_response.text = "```c\npatched_c_code\n```"
    mock_client.models.generate_content.return_value = mock_response

    engine = GeminiEngine(api_key="test_gemini_key")
    patch_code = engine.generate_patch("source", {"vuln_type": "test"})
    assert patch_code == "patched_c_code"

    mock_response.text = "```c\nrefined_c_code\n```"
    refined_patch = engine.refine_patch("source", "bad_patch", "compiler error", {"vuln_type": "test"})
    assert refined_patch == "refined_c_code"

    mock_response.text = "```python\nexploit_python_code\n```"
    exploit_code = engine.generate_exploit("source", {"args": ["x"]}, "exe_path", "args")
    assert exploit_code == "exploit_python_code"


# --- OPENAI ENGINE TESTS ----------------------------------------------------

@patch("openai.OpenAI")
def test_openai_engine_analyze_code(mock_openai_class):
    mock_client = MagicMock()
    mock_openai_class.return_value = mock_client
    
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = json.dumps([
        {
            "args": ["openai_payload"],
            "input_data": "",
            "vuln_type": "format_string",
            "reason": "printf",
            "severity": "high",
            "cwe": "CWE-134"
        }
    ])
    mock_client.chat.completions.create.return_value = mock_completion

    engine = OpenAIEngine(api_key="test_openai_key", model="gpt-4o")
    payloads = engine.analyze_code("int main() { return 0; }", 3, "args", False)

    assert len(payloads) == 1
    assert payloads[0]["vuln_type"] == "format_string"
    assert payloads[0]["args"] == ["openai_payload"]
    
    called_kwargs = mock_client.chat.completions.create.call_args[1]
    assert called_kwargs["model"] == "gpt-4o"
    assert called_kwargs["response_format"] == {"type": "json_object"}


@patch("openai.OpenAI")
def test_openai_engine_refine_payload(mock_openai_class):
    mock_client = MagicMock()
    mock_openai_class.return_value = mock_client
    
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = json.dumps({
        "payloads": [
            {
                "args": ["refined_openai"],
                "input_data": "",
                "vuln_type": "format_string",
                "reason": "retry",
                "severity": "high",
                "cwe": "CWE-134"
            }
        ]
    })
    mock_client.chat.completions.create.return_value = mock_completion

    engine = OpenAIEngine(api_key="test_openai_key")
    payloads = engine.refine_payload(
        source_code="int main() { return 0; }",
        failed_args=["f1"],
        failed_input="",
        stdout="ok",
        stderr="",
        return_code=0,
        delivery_mode="args"
    )

    assert len(payloads) == 1
    assert payloads[0]["args"] == ["refined_openai"]


@patch("openai.OpenAI")
def test_openai_engine_generate_patch_and_exploit(mock_openai_class):
    mock_client = MagicMock()
    mock_openai_class.return_value = mock_client
    
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = "```c\npatched_c_by_openai\n```"
    mock_client.chat.completions.create.return_value = mock_completion

    engine = OpenAIEngine(api_key="test_openai_key")
    patch_code = engine.generate_patch("source", {"vuln_type": "test"})
    assert patch_code == "patched_c_by_openai"

    mock_completion.choices[0].message.content = "```c\nrefined_c_by_openai\n```"
    refined_patch = engine.refine_patch("source", "bad_patch", "compiler error", {"vuln_type": "test"})
    assert refined_patch == "refined_c_by_openai"

    mock_completion.choices[0].message.content = "```python\nexploit_py_by_openai\n```"
    exploit_code = engine.generate_exploit("source", {"args": ["x"]}, "exe_path", "args")
    assert exploit_code == "exploit_py_by_openai"


# --- OLLAMA ENGINE TESTS ----------------------------------------------------

@patch("requests.post")
def test_ollama_engine_analyze_code(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": json.dumps([
            {
                "args": ["ollama_payload"],
                "vuln_type": "use_after_free",
                "reason": "free then write",
                "severity": "critical",
                "cwe": "CWE-416"
            }
        ])
    }
    mock_post.return_value = mock_response

    engine = OllamaEngine(model="llama3.2")
    payloads = engine.analyze_code("int main() { return 0; }", 2, "args", False)

    assert len(payloads) == 1
    assert payloads[0]["vuln_type"] == "use_after_free"
    assert payloads[0]["args"] == ["ollama_payload"]
    
    called_kwargs = mock_post.call_args[1]
    assert called_kwargs["json"]["model"] == "llama3.2"
    assert called_kwargs["json"]["format"] == "json"


@patch("requests.post")
def test_ollama_engine_refine_payload(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": json.dumps([
            {
                "args": ["refined_ollama"],
                "vuln_type": "use_after_free",
                "reason": "retry",
                "severity": "critical",
                "cwe": "CWE-416"
            }
        ])
    }
    mock_post.return_value = mock_response

    engine = OllamaEngine()
    payloads = engine.refine_payload(
        source_code="int main() { return 0; }",
        failed_args=["f1"],
        failed_input="",
        stdout="",
        stderr="",
        return_code=0,
        delivery_mode="args"
    )

    assert len(payloads) == 1
    assert payloads[0]["args"] == ["refined_ollama"]


@patch("requests.post")
def test_ollama_engine_generate_patch_and_exploit(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": "```c\npatched_c_by_ollama\n```"}
    mock_post.return_value = mock_response

    engine = OllamaEngine()
    patch_code = engine.generate_patch("source", {"vuln_type": "test"})
    assert patch_code == "patched_c_by_ollama"

    mock_response.json.return_value = {"response": "```c\nrefined_c_by_ollama\n```"}
    refined_patch = engine.refine_patch("source", "bad_patch", "compiler error", {"vuln_type": "test"})
    assert refined_patch == "refined_c_by_ollama"

    mock_response.json.return_value = {"response": "```python\nexploit_py_by_ollama\n```"}
    exploit_code = engine.generate_exploit("source", {"args": ["x"]}, "exe_path", "args")
    assert exploit_code == "exploit_py_by_ollama"
