import json
import time
from rich.console import Console
from mutagen.engines.base import BaseEngine

console = Console(force_terminal=True, force_jupyter=False)

class OpenAIEngine(BaseEngine):
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.api_key = api_key
        self.model = model or "gpt-4o-mini"
        from openai import OpenAI
        self.client = OpenAI(api_key=self.api_key)

    def analyze_code(self, source_code: str, max_payloads: int, debug: bool) -> list[dict]:
        prompt = f"""You are an expert defensive security researcher conducting a code audit.
Your job is to analyze the following C source code for potential vulnerabilities.

SOURCE CODE:
```c
{source_code}
```

IMPORTANT RULES:
1. Return a JSON array of payloads.
2. Each element must have these fields:
   - "args": an array of strings, one per command-line argument (e.g. ["AAAA...", "delete"])
   - "vuln_type": the vulnerability type (e.g. "buffer_overflow", "format_string", "integer_overflow", "use_after_free")
   - "reason": brief explanation of why this triggers the bug, containing your chain of thought logic
   - "severity": "critical", "high", "medium", or "low"
   - "cwe": the CWE ID if known (e.g. "CWE-120")
3. Limit repeated strings to 1000 characters.
4. Generate up to {max_payloads} diverse payloads.
5. Study the main() function for argument count.

Respond with ONLY the JSON array."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                response_format={"type": "json_object"} if "gpt-4" in self.model or "gpt-3.5" in self.model or "o1" in self.model else None
            )
            raw = response.choices[0].message.content.strip()
            if debug:
                with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                    f.write(f"--- OpenAI ANALYZE CODE RAW RESPONSE ---\n{raw}\n\n")
            
            data = json.loads(raw)
            # OpenAI response_format json_object returns an object, so if it's not a list, extract the list
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        return v
                return [data]
            return data
        except Exception as e:
            console.print(f"[red]OpenAI analysis failed: {e}[/red]")
            return []

    def refine_payload(self, source_code: str, failed_args: list[str], stdout: str, stderr: str, return_code: int) -> list[dict]:
        prompt = f"""You are an expert defensive security researcher. You previously analyzed this C source code to find vulnerabilities.
Your previous payload DID NOT CRASH the target program. We need to refine the attack.

SOURCE CODE:
```c
{source_code}
```

PREVIOUS PAYLOAD ARGS:
{failed_args}

EXECUTION RESULTS:
- Exit Code: {return_code}
- Stdout: {stdout.strip() if stdout else "None"}
- Stderr: {stderr.strip() if stderr else "None"}

Please analyze why the previous payload failed to cause a crash.
Generate 2-3 new, refined payloads in a JSON array.

Respond with ONLY the JSON array."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.8,
                response_format={"type": "json_object"}
            )
            raw = response.choices[0].message.content.strip()
            data = json.loads(raw)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        return v
                return [data]
            return data
        except Exception as e:
            console.print(f"[red]OpenAI refinement failed: {e}[/red]")
            return []

    def generate_patch(self, source_code: str, crash_data: dict, debug: bool = False) -> str:
        prompt = f"""You are a Senior C Security Engineer. Securely patch this C code:
{source_code}

Vulnerability details:
- Args: {crash_data.get("args")}
- Vuln: {crash_data.get("vuln_type")}
- Reason: {crash_data.get("reason")}

Provide the ENTIRE patched C code file. No markdown block formatting, return raw C code only."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            text = response.choices[0].message.content.strip()
            if text.startswith("```c"):
                text = text[4:]
            elif text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
            return text.strip()
        except Exception as e:
            if debug:
                console.print(f"[red]OpenAI patch failed: {e}[/red]")
            return ""

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, debug: bool = False) -> str:
        prompt = f"""You are a Senior Security QA Engineer writing a regression test.
Write a standalone Python 3 script reproducing the vulnerability in this compiled binary '{exe_path}':
C Code:
{source_code}

Crash args: {crash_data.get("args")}

Provide the ENTIRE Python script. No markdown formatting outside of the code block. Return raw Python code only."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            text = response.choices[0].message.content.strip()
            if text.startswith("```python"):
                text = text[9:]
            elif text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
            return text.strip()
        except Exception as e:
            if debug:
                console.print(f"[red]OpenAI exploit generation failed: {e}[/red]")
            return ""
