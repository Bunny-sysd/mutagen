import json
import time
from rich.console import Console
from mutagen.engines.base import BaseEngine

console = Console(force_terminal=True, force_jupyter=False)

class OllamaEngine(BaseEngine):
    def __init__(self, model: str = "llama3.2"):
        self.model = model or "llama3.2"
        import requests
        self.requests = requests
        self.url = "http://localhost:11434/api/generate"

    def _generate(self, prompt: str, system: str = "", format_json: bool = False) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.5
            }
        }
        if system:
            payload["system"] = system
        if format_json:
            payload["format"] = "json"

        try:
            response = self.requests.post(self.url, json=payload, timeout=60)
            if response.status_code == 200:
                return response.json().get("response", "").strip()
            else:
                console.print(f"[red]Ollama error: HTTP {response.status_code}[/red]")
                return ""
        except Exception as e:
            console.print(f"[red]Ollama connection failed: {e}[/red]")
            return ""

    def analyze_code(self, source_code: str, max_payloads: int, debug: bool) -> list[dict]:
        prompt = f"""Analyze this C source code for vulnerabilities and return a JSON list of fuzzing payloads.
SOURCE CODE:
{source_code}

Format output as a JSON array of objects.
Each object must have these fields:
- "args": array of strings (arguments)
- "vuln_type": string (vulnerability type)
- "reason": string (explanation)
- "severity": "critical", "high", "medium", or "low"
- "cwe": string (CWE ID)

Generate up to {max_payloads} payloads. Study main() for argument count."""
        raw = self._generate(prompt, format_json=True)
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- Ollama ANALYZE CODE RAW RESPONSE ---\n{raw}\n\n")
        try:
            return json.loads(raw)
        except Exception:
            try:
                # Sometimes Ollama wraps list in an object
                data = json.loads(raw)
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, list):
                            return v
                    return [data]
                return data
            except Exception:
                console.print(f"[red]Failed to parse Ollama JSON: {raw[:300]}[/red]")
                return []

    def refine_payload(self, source_code: str, failed_args: list[str], stdout: str, stderr: str, return_code: int) -> list[dict]:
        prompt = f"""We are fuzzing this C code:
{source_code}

The payload {failed_args} did not crash the program.
Exit code was {return_code}.
Stdout: {stdout}
Stderr: {stderr}

Generate 2-3 refined payloads in a JSON list to bypass the validation or cause a crash."""
        raw = self._generate(prompt, format_json=True)
        try:
            return json.loads(raw)
        except Exception:
            return []

    def generate_patch(self, source_code: str, crash_data: dict, debug: bool = False) -> str:
        prompt = f"""Securely patch the vulnerability in this C code:
{source_code}

Vulnerability: {crash_data.get("vuln_type")}
Args: {crash_data.get("args")}

Return only the updated C source code file. Do not include markdown blocks, explanations, or backticks."""
        text = self._generate(prompt)
        if text.startswith("```c"):
            text = text[4:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, debug: bool = False) -> str:
        prompt = f"""Write a Python 3 regression test script that calls '{exe_path}' with args {crash_data.get("args")} to reproduce the crash.
C source code:
{source_code}

Return only the Python script code. No markdown blocks, explanations, or backticks."""
        text = self._generate(prompt)
        if text.startswith("```python"):
            text = text[9:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()
