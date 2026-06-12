import json
import time
from google import genai
from rich.console import Console

from mutagen.models import FuzzPayload
from mutagen.engines.base import BaseEngine

console = Console(force_terminal=True, force_jupyter=False)

class GeminiEngine(BaseEngine):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = genai.Client(api_key=self.api_key)

    def analyze_code(self, source_code: str, max_payloads: int, debug: bool) -> list[dict]:
        prompt = f"""You are an expert defensive security researcher conducting a code audit.
Your job is to analyze the following C source code for potential vulnerabilities
such as buffer overflows, format string bugs, integer overflows, use-after-free,
off-by-one errors, double-free, heap overflows, and command injection.

First, analyze the source code step by step using a Chain of Thought process to understand
the control flow, data flow, and memory management. Identify where untrusted inputs 
are used in dangerous operations without proper validation or bounds checking.

For each vulnerability you find, generate a specific test payload that would
trigger the bug when passed as command-line arguments to the compiled program.

SOURCE CODE:
```c
{source_code}
```

IMPORTANT RULES:
1. Return a JSON array of payloads matching the requested schema.
2. Each element must have these fields:
   - "args": an array of strings, one per command-line argument (e.g. ["AAAA...", "delete"])
   - "vuln_type": the vulnerability type (e.g. "buffer_overflow", "format_string", "integer_overflow", "use_after_free")
   - "reason": brief explanation of why this triggers the bug, containing your chain of thought logic
   - "severity": "critical", "high", "medium", or "low"
   - "cwe": the CWE ID if known (e.g. "CWE-120")
3. For long repeated strings, write them out literally (e.g. "AAAAAAAAAA" not "A"*10). Limit any repeated strings to a maximum of 1000 characters to prevent parsing truncation.
4. Generate up to {max_payloads} diverse payloads ranging from safe inputs to crash-inducing.
5. Study the main() function to see exactly how many arguments the program expects."""

        models_to_try = ["gemini-2.5-flash-lite", "gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"]
        response = None
        for model_name in models_to_try:
            for attempt in range(3):
                try:
                    console.print(f"[dim]  Trying model: {model_name} (attempt {attempt + 1})...[/dim]")
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={
                            "temperature": 0.7,
                            "response_mime_type": "application/json",
                            "response_schema": list[FuzzPayload],
                            "safety_settings": [
                                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                            ],
                        },
                    )
                    break
                except Exception as e:
                    error_msg = str(e)
                    if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "503" in error_msg or "UNAVAILABLE" in error_msg:
                        wait_time = (attempt + 1) * 20
                        console.print(f"[yellow]  Rate limited or model overloaded. Waiting {wait_time}s before retry...[/yellow]")
                        time.sleep(wait_time)
                    else:
                        console.print(f"[red]  Error: {error_msg[:200]}[/red]")
                        break
            if response is not None:
                break

        if response is None:
            console.print("[red]!! All models failed. Check your API key or try again later.[/red]")
            return []

        raw = response.text.strip()
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- AI ANALYZE CODE RAW RESPONSE ---\n{raw}\n\n")
        try:
            payloads = json.loads(raw)
            return payloads
        except json.JSONDecodeError:
            console.print(f"[red]!! Could not parse AI response as JSON.[/red]")
            console.print(f"[dim]First 300 chars: {raw[:300]}[/dim]")
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

Please analyze why the previous payload failed to cause a memory corruption/crash (e.g., did it fail a length check? Was it not long enough? Did it hit an early exit?).
Generate 2-3 new, refined payloads to try to bypass the mitigation or hit the vulnerability correctly.

IMPORTANT RULES:
1. Respond ONLY with a valid JSON array. No markdown, no explanation outside JSON.
2. Each element must have these fields:
   - "args": an array of strings, one per command-line argument
   - "vuln_type": the vulnerability type
   - "reason": brief explanation of why THIS new payload will succeed where the last one failed
   - "severity": "critical", "high", "medium", or "low"
   - "cwe": the CWE ID if known
3. For long repeated strings, write them out literally (e.g. "AAAAAAAAAA"). Limit any repeated strings to a maximum of 1000 characters to prevent parsing truncation.

Respond with ONLY the JSON array."""

        models_to_try = ["gemini-2.5-flash-lite", "gemini-2.5-flash", "gemini-2.0-flash"]
        response = None
        for model_name in models_to_try:
            for attempt in range(2):
                try:
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={
                            "temperature": 0.8,
                            "response_mime_type": "application/json",
                            "response_schema": list[FuzzPayload],
                            "safety_settings": [
                                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                            ],
                        },
                    )
                    break
                except Exception as e:
                    error_msg = str(e)
                    if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "503" in error_msg or "UNAVAILABLE" in error_msg:
                        wait_time = (attempt + 1) * 10
                        console.print(f"[yellow]  Rate limited on refinement. Waiting {wait_time}s before retry...[/yellow]")
                        time.sleep(wait_time)
                    else:
                        console.print(f"[red]  Error during refinement: {error_msg[:200]}[/red]")
                        break
            if response is not None:
                break

        if response is None:
            return []

        raw = response.text.strip()
        with open("mutagen_debug.log", "a", encoding="utf-8") as f:
            f.write(f"--- AI REFINE PAYLOAD RAW RESPONSE ---\n{raw}\n\n")
        try:
            payloads = json.loads(raw)
            return payloads
        except json.JSONDecodeError:
            return []

    def generate_patch(self, source_code: str, crash_data: dict, debug: bool = False) -> str:
        prompt = f"""You are a Senior C Security Engineer.
An automated fuzzer just found a critical vulnerability in the following C code.

SOURCE CODE:
```c
{source_code}
```

CRASHING PAYLOAD ARGS:
{crash_data.get("args")}

VULNERABILITY DETECTED:
{crash_data.get("vuln_type")}

REASONING:
{crash_data.get("reason")}

CRASH TYPE:
{crash_data.get("crash_type")}

Your task is to securely patch the vulnerability.
Provide the ENTIRE updated C source code file that fixes the issue.
DO NOT use markdown formatting outside of the code block.
Return ONLY the raw C code. DO NOT wrap it in ```c and ```.
If you must use markdown, the parser will try to strip it, but please try to return just the C code."""

        models_to_try = ["gemini-2.5-flash-lite", "gemini-2.5-flash", "gemini-2.0-flash"]
        response = None
        for model_name in models_to_try:
            for attempt in range(2):
                try:
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={
                            "temperature": 0.2,
                            "safety_settings": [
                                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                            ],
                        },
                    )
                    break
                except Exception as e:
                    if debug:
                        console.print(f"[red]Error in generate_patch ({model_name}): {e}[/red]")
                    time.sleep((attempt + 1) * 5)
            if response is not None:
                break

        if response is None:
            return ""

        text = response.text.strip()
        if text.startswith("```c"):
            text = text[4:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]

        return text.strip()

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, debug: bool = False) -> str:
        prompt = f"""You are a Senior Security QA Engineer writing a regression test.
An automated fuzzer just found a memory corruption vulnerability in the following C code compiled as '{exe_path}'.

SOURCE CODE:
```c
{source_code}
```

CRASHING PAYLOAD ARGS:
{crash_data.get("args")}

VULNERABILITY DETECTED:
{crash_data.get("vuln_type")}

CRASH TYPE:
{crash_data.get("crash_type")}

Your task is to write a standalone Python 3 Proof of Concept (PoC) script that reliably reproduces this vulnerability against the compiled executable.
This PoC will be used to verify our patch.
CRITICAL: The script MUST accept an optional command-line argument for the target executable path via sys.argv. If no argument is provided, it should default to '{exe_path}'.
Use the `subprocess` module to pass the crashing payload arguments to the executable.
Include comments explaining how the payload triggers the memory corruption.

Provide the ENTIRE Python script.
DO NOT use markdown formatting outside of the code block.
Return ONLY the raw Python code. DO NOT wrap it in ```python and ```.
If you must use markdown, the parser will try to strip it, but please try to return just the Python code."""

        models_to_try = ["gemini-2.5-flash-lite", "gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"]
        response = None
        for model_name in models_to_try:
            for attempt in range(2):
                try:
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={
                            "temperature": 0.3,
                            "safety_settings": [
                                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                            ],
                        },
                    )
                    break
                except Exception as e:
                    time.sleep((attempt + 1) * 5)
            if response is not None:
                break

        if response is None:
            return ""

        text = response.text.strip()
        if text.startswith("```python"):
            text = text[9:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]

        return text.strip()
