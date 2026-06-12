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

    def analyze_code(self, source_code: str, max_payloads: int, delivery_mode: str, debug: bool) -> list[dict]:
        prompt = f"""You are an expert defensive security researcher conducting a code audit.
Your job is to analyze the following C source code for potential vulnerabilities
such as buffer overflows, format string bugs, integer overflows, use-after-free,
off-by-one errors, double-free, heap overflows, and command injection.

The target program receives input via: {delivery_mode}.

First, analyze the source code step by step using a Chain of Thought process to understand
the control flow, data flow, and memory management. Identify where untrusted inputs 
are used in dangerous operations without proper validation or bounds checking.

For each vulnerability you find, generate a specific test payload.

SOURCE CODE:
```c
{source_code}
```

IMPORTANT RULES:
1. Return a JSON array of payloads.
2. Each element must have these fields:
   - "args": an array of strings, one per command-line argument (used if delivery mode is 'args')
   - "input_data": a string containing the raw input to feed via stdin or network (used if delivery mode is 'stdin' or 'tcp')
   - "vuln_type": the vulnerability type (e.g. "buffer_overflow", "format_string", "integer_overflow", "use_after_free")
   - "reason": brief explanation of why this triggers the bug, containing your chain of thought logic
   - "severity": "critical", "high", "medium", or "low"
   - "cwe": the CWE ID if known (e.g. "CWE-120")
3. For long repeated strings, write them out literally (e.g. "AAAAAAAAAA" not "A"*10). Limit any repeated strings to a maximum of 1000 characters to prevent parsing truncation.
4. Generate up to {max_payloads} diverse payloads ranging from safe inputs to crash-inducing.
5. Study the main() function to see exactly how the program reads its input (e.g., argv, fgets, scanf, recv).

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

    def refine_payload(self, source_code: str, failed_args: list[str], failed_input: str, stdout: str, stderr: str, return_code: int, delivery_mode: str) -> list[dict]:
        prompt = f"""You are an expert defensive security researcher. You previously analyzed this C source code to find vulnerabilities.
Your previous payload DID NOT CRASH the target program. We need to refine the attack.

The target program receives input via: {delivery_mode}.

SOURCE CODE:
```c
{source_code}
```

PREVIOUS PAYLOAD DETAILS:
- Args: {failed_args}
- Input Data: {failed_input}

EXECUTION RESULTS:
- Exit Code: {return_code}
- Stdout: {stdout.strip() if stdout else "None"}
- Stderr: {stderr.strip() if stderr else "None"}

Please analyze why the previous payload failed to cause a memory corruption/crash.
Generate 2-3 new, refined payloads to try to bypass the mitigation or hit the vulnerability correctly.

IMPORTANT RULES:
1. Respond ONLY with a valid JSON array matching the requested schema.
2. Each element must have these fields:
   - "args": an array of strings, one per command-line argument (used if delivery mode is 'args')
   - "input_data": a string containing the raw input to feed via stdin or network (used if delivery mode is 'stdin' or 'tcp')
   - "vuln_type": the vulnerability type
   - "reason": brief explanation of why THIS new payload will succeed where the last one failed
   - "severity": "critical", "high", "medium", or "low"
   - "cwe": the CWE ID if known
3. For long repeated strings, write them out literally (e.g. "AAAAAAAAAA"). Limit any repeated strings to a maximum of 1000 characters to prevent parsing truncation.

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

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, delivery_mode: str, debug: bool = False) -> str:
        prompt = f"""You are a Senior Security QA Engineer writing a regression test.
An automated fuzzer just found a memory corruption vulnerability in the following C code compiled as '{exe_path}'.

The executable expects input via: {delivery_mode}.

SOURCE CODE:
```c
{source_code}
```

CRASHING PAYLOAD ARGS:
{crash_data.get("args")}

CRASHING PAYLOAD INPUT DATA:
{crash_data.get("input_data")}

VULNERABILITY DETECTED:
{crash_data.get("vuln_type")}

CRASH TYPE:
{crash_data.get("crash_type")}

Your task is to write a standalone Python 3 Proof of Concept (PoC) script that reliably reproduces this vulnerability against the compiled executable.
This PoC will be used to verify our patch.
CRITICAL: The script MUST accept an optional command-line argument for the target executable path via sys.argv. If no argument is provided, it should default to '{exe_path}'.

- If delivery mode is 'args', the script must launch the program with the crash args as command-line arguments.
- If delivery mode is 'stdin', the script must launch the program and feed the raw input data into its stdin stream using `subprocess.communicate` or similar.
- If delivery mode is 'tcp:<port>', the script must launch the program, wait a moment for the server to bind to the port, connect to 127.0.0.1 on the specified port using the `socket` module, and send the input data over the socket.

Include comments explaining how the payload triggers the memory corruption.

Provide the ENTIRE Python script.
DO NOT use markdown formatting outside of the code block.
Return ONLY the raw Python code. DO NOT wrap it in ```python and ```.
If you must use markdown, the parser will try to strip it, but please try to return just the Python code."""
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
