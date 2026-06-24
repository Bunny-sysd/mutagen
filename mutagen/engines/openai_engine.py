import json
import time

from rich.console import Console

from mutagen.engines.base import BaseEngine

console = Console(force_terminal=True, force_jupyter=False)

class OpenAIEngine(BaseEngine):
    def __init__(self, api_key: str, model: str = "gpt-4o-mini", debug: bool = False):
        self.api_key = api_key
        self.model = model or "gpt-4o-mini"
        self.debug = debug
        from openai import OpenAI
        self.client = OpenAI(api_key=self.api_key)

    def _create_chat_completion(self, **kwargs) -> any:
        for attempt in range(3):
            try:
                return self.client.chat.completions.create(**kwargs)
            except Exception as e:
                err_str = str(e).lower()
                if "rate limit" in err_str or "429" in err_str or "quota" in err_str:
                    wait_time = 20
                    console.print(f"[yellow]  Rate limit (429) hit on OpenAI. Waiting {wait_time}s to cool down...[/yellow]")
                    time.sleep(wait_time)
                elif "500" in err_str or "503" in err_str or "timeout" in err_str:
                    wait_time = (attempt + 1) * 5
                    console.print(f"[yellow]  OpenAI transient error. Waiting {wait_time}s before retry...[/yellow]")
                    time.sleep(wait_time)
                else:
                    raise e
        raise Exception("OpenAI API call failed after multiple retries.")

    def analyze_code(self, source_code: str, max_payloads: int, delivery_mode: str, debug: bool, profile: str = "legacy-audit") -> list[dict]:
        decompile_context = ""
        if getattr(self, "is_decompiled", False):
            decompile_context = """
CRITICAL CONTEXT: This is DECOMPILED pseudo-C code extracted from a compiled binary via Ghidra.
- Variable names are auto-generated (e.g., param_1, iVar2, local_28) — infer their purpose from usage.
- Some constructs may be approximated by the decompiler and may not match the original source exactly.
- Focus on security patterns, buffer operations, pointer arithmetic, unsafe casts, and control flow.
- The original binary may have been compiled from C, C++, or another language.

"""
        if profile == "supply-chain":
            focus_description = "unauthorized network calls, hardcoded backdoors, hidden command execution, environment variable exfiltration, and secrets/credential leaks."
            vuln_types_example = '"backdoor", "credential_leak", "command_injection", "unauthorized_socket"'
        elif profile == "malware-triage":
            focus_description = "malware signatures, encryption algorithms (e.g., ransomware encryption loops), persistence mechanisms, keyloggers, evasion techniques, and command & control (C2) footprint."
            vuln_types_example = '"malware_persistence", "ransomware_encryption", "keylogger_module", "c2_socket"'
        else:
            focus_description = "buffer overflows, format string bugs, integer overflows, use-after-free, off-by-one errors, double-free, heap overflows, and command injection."
            vuln_types_example = '"buffer_overflow", "format_string", "integer_overflow", "use_after_free"'

        prompt = f"""You are an expert defensive security auditor.
{decompile_context}Analyze this {self.lang_name} code for potential vulnerabilities & security risks, guided by the MITRE ATT&CK and CWE frameworks, focusing on: {focus_description}

Input delivery mode: {delivery_mode}.

Perform a token-efficient data & control flow audit to identify potential vulnerability/triage trigger inputs.

SOURCE CODE:
```{self.lang_ext}
{source_code}
```

RULES:
1. Return a JSON array of payloads matching the requested schema.
2. Fields for each element:
   - "args": array of command-line argument strings (for 'args' mode). Do not include shell pipes ("|"), redirections (">", "<"), or echo command wrappers.
   - "input_data": raw input string (for 'stdin' or 'tcp' mode).
   - "vuln_type": vulnerability/capability name (e.g. {vuln_types_example}).
   - "reason": extremely concise summary (max 2 sentences) mapping the exploit logic directly to MITRE ATT&CK techniques/tactics.
   - "severity": "critical", "high", "medium", or "low".
   - "cwe": CWE ID if known (e.g., "CWE-120").
   - "data_flow": array of execution step strings tracing flow from input (Source) to vulnerability/trigger (Sink).
   - "confidence_score": integer (1-10) assessing likelihood of trigger success.
   - "mitigations_detected": array of detected input checks/filters.
3. No repeating character math (use literal strings, max 1000 chars).
4. Generate up to {max_payloads} diverse payloads (safe to risk-inducing).

Respond with ONLY the JSON array."""

        try:
            response = self._create_chat_completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                response_format={"type": "json_object"} if ("gpt-4" in self.model or "gpt-3.5" in self.model) and "o1" not in self.model else None
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
        prompt = f"""You are an expert defensive security researcher. You previously analyzed this {self.lang_name} source code to find vulnerabilities.
Your previous payload DID NOT CRASH the target program. We need to refine the attack.

The target program receives input via: {delivery_mode}.

SOURCE CODE:
```{self.lang_ext}
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
            response = self._create_chat_completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.8,
                response_format={"type": "json_object"} if ("gpt-4" in self.model or "gpt-3.5" in self.model) and "o1" not in self.model else None
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
        prompt = f"""You are a Senior {self.lang_name} Security Engineer. Securely patch this {self.lang_name} code:
{source_code}

Vulnerability details:
- Args: {crash_data.get("args")}
- Vuln: {crash_data.get("vuln_type")}
- Reason: {crash_data.get("reason")}

Provide the ENTIRE patched {self.lang_name} code file. No markdown block formatting, return raw {self.lang_name} code only."""
        try:
            response = self._create_chat_completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            text = response.choices[0].message.content.strip()
            for prefix in (f"```{self.lang_ext}", "```rust", "```c", "```"):
                if text.lower().startswith(prefix):
                    text = text[len(prefix):]
                    break
            if text.endswith("```"):
                text = text[:-3]
            return text.strip()
        except Exception as e:
            if debug:
                console.print(f"[red]OpenAI patch failed: {e}[/red]")
            return ""

    def refine_patch(self, source_code: str, bad_patch: str, error_message: str, crash_data: dict, debug: bool = False) -> str:
        prompt = f"""You are a Senior {self.lang_name} Security Engineer.
We tried to patch a vulnerability in the following {self.lang_name} code, but the patch failed.

ORIGINAL SOURCE CODE:
```{self.lang_ext}
{source_code}
```

VULNERABILITY DETAILS:
- Vulnerability: {crash_data.get("vuln_type")}
- CWE: {crash_data.get("cwe")}
- Severity: {crash_data.get("severity")}
- Exploit Payload Args: {crash_data.get("args")}
- Exploit Payload Input Data: {crash_data.get("input_data")}

THE ATTEMPTED PATCH CODE THAT FAILED:
```{self.lang_ext}
{bad_patch}
```

FAILURE DETAILS:
{error_message}

Please analyze the failure details and correct the patch code.
Provide the ENTIRE corrected {self.lang_name} source code file.
DO NOT use markdown formatting outside of the code block.
Return ONLY the raw {self.lang_name} code. DO NOT wrap it in ```{self.lang_ext} and ```."""
        try:
            response = self._create_chat_completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            text = response.choices[0].message.content.strip()
            for prefix in (f"```{self.lang_ext}", "```rust", "```c", "```"):
                if text.lower().startswith(prefix):
                    text = text[len(prefix):]
                    break
            if text.endswith("```"):
                text = text[:-3]
            return text.strip()
        except Exception as e:
            if debug:
                console.print(f"[red]OpenAI refine_patch failed: {e}[/red]")
            return ""

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, delivery_mode: str, debug: bool = False) -> str:
        prompt = f"""You are a Senior Security QA Engineer writing a regression test.
An automated fuzzer just found a security vulnerability in the following {self.lang_name} code compiled as '{exe_path}'.

The executable expects input via: {delivery_mode}.

SOURCE CODE:
```{self.lang_ext}
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
            response = self._create_chat_completion(
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

    def deobfuscate_code(self, raw_code: str, debug: bool = False) -> str:
        prompt = f"""You are an expert reverse engineer and code deobfuscator.
Your task is to analyze the following messy decompiled C pseudo-code and perform symbol recovery and deobfuscation to make it readable.

Follow these rules:
1. Rename all generic, auto-generated variables (like local_1c, param_1, pvVar2, iVar3) to clear, descriptive names based on how they are used in the code.
2. Rename generic auto-generated function names (like FUN_004010a0, FUN_004011b0) to meaningful descriptive names based on their logic.
3. Clean up complex control-flow loops or ternary statements into standard, structured C code equivalents.
4. Add clear inline comments explaining what each logical block does.
5. Provide the ENTIRE refactored, readable C source code file.
6. Do NOT include any markdown block formatting or explanations outside of the code block. Return ONLY raw C code. DO NOT wrap it in ```c and ```.

RAW DECOMPILED PSEUDO-CODE:
```c
{raw_code}
```

Return ONLY the refactored, commented, and readable C code."""
        try:
            response = self._create_chat_completion(
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
                console.print(f"[red]OpenAI deobfuscation failed: {e}[/red]")
            return raw_code

