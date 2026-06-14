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

    def analyze_code(self, source_code: str, max_payloads: int, delivery_mode: str, debug: bool) -> list[dict]:
        prompt = f"""Analyze this C source code for potential vulnerabilities (buffer overflows, format string bugs, integer overflows, use-after-free, etc.).
The target program receives input via: {delivery_mode}.

SOURCE CODE:
{source_code}

Format output as a JSON array of objects.
Each object must have these fields:
- "args": array of strings (used if delivery mode is 'args')
- "input_data": string containing raw input data (used if delivery mode is 'stdin' or 'tcp')
- "vuln_type": string (vulnerability type)
- "reason": string (explanation)
- "severity": "critical", "high", "medium", or "low"
- "cwe": string (CWE ID)

Generate up to {max_payloads} payloads. Study main() for how input is read."""
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

    def refine_payload(self, source_code: str, failed_args: list[str], failed_input: str, stdout: str, stderr: str, return_code: int, delivery_mode: str) -> list[dict]:
        prompt = f"""We are fuzzing this C code where input is delivered via {delivery_mode}:
{source_code}

Previous attempt details:
- Args: {failed_args}
- Input data: {failed_input}
- Exit code was: {return_code}
- Stdout: {stdout}
- Stderr: {stderr}

Generate 2-3 refined payloads in a JSON list (containing both "args" and "input_data" fields) to bypass validation or cause a crash."""
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

    def refine_patch(self, source_code: str, bad_patch: str, error_message: str, crash_data: dict, debug: bool = False) -> str:
        prompt = f"""We tried to patch a vulnerability in the following C code, but the patch failed.

ORIGINAL SOURCE CODE:
{source_code}

VULNERABILITY DETAILS:
- Vulnerability: {crash_data.get("vuln_type")}
- Args: {crash_data.get("args")}

THE ATTEMPTED PATCH CODE THAT FAILED:
{bad_patch}

FAILURE DETAILS:
{error_message}

Please analyze the failure details and correct the patch code.
Provide the ENTIRE corrected C source code file.
DO NOT use markdown formatting outside of the code block.
Return ONLY the raw C code. DO NOT wrap it in ```c and ```."""
        text = self._generate(prompt)
        if text.startswith("```c"):
            text = text[4:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, delivery_mode: str, debug: bool = False) -> str:
        prompt = f"""Write a standalone Python 3 script reproducing the crash in '{exe_path}' where input delivery is via '{delivery_mode}'.
C Code:
{source_code}

Crash args: {crash_data.get("args")}
Crash input data: {crash_data.get("input_data")}

The Python script must accept an optional target executable path command-line argument (sys.argv[1]), defaulting to '{exe_path}', and execute it appropriately using subprocess or socket.
Return only the Python script code. No markdown blocks, explanations, or backticks."""
        text = self._generate(prompt)
        if text.startswith("```python"):
            text = text[9:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()
