import json
import time

from google import genai
from rich.console import Console

from mutagen.engines.base import BaseEngine

console = Console(force_terminal=True, force_jupyter=False)

class GeminiEngine(BaseEngine):
    def __init__(self, api_key: str, model: str = "", debug: bool = False):
        self.api_key = api_key
        self.model = model
        self.debug = debug
        self.client = genai.Client(api_key=self.api_key)
        # Override internal HTTP clients with custom timeouts to bypass connect/handshake timeout errors in this environment
        import httpx
        custom_timeout = httpx.Timeout(15.0, connect=5.0, read=10.0, write=10.0)
        self.client._http_client = httpx.Client(timeout=custom_timeout, http2=False)
        self.client._async_http_client = httpx.AsyncClient(timeout=custom_timeout, http2=False)

    def _classify_and_handle_error(self, e: Exception, attempt: int) -> tuple[str, int]:
        import httpx
        err_str = str(e).upper()

        # 1. Check for connection/network/handshake/timeout errors
        is_network = False
        if isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.NetworkError)):
            is_network = True
        elif any(k in err_str for k in ["CONNECTTIMEOUT", "CONNECTERROR", "READTIMEOUT", "TLS", "SSL", "HANDSHAKE", "NAMERESOLUTIONERROR", "CONNECTION REFUSED", "TIMEOUT"]):
            is_network = True

        if is_network:
            console.print("[red]  Network connection or TLS handshake failure detected.[/red]")
            console.print("[yellow]  Skipping Gemini API calls. Mutagen will fall back to local traditional/offline fuzzing.[/yellow]")
            return "abort_all", 0

        # 2. Check for invalid API key / auth errors
        if any(k in err_str for k in ["API_KEY_INVALID", "API KEY NOT VALID", "INVALID_API_KEY", "APIKEY"]):
            console.print("[red]  Critical Auth Error: The provided Gemini API Key is invalid.[/red]")
            return "abort_all", 0

        # 3. Check for 429 Resource Exhausted (Rate Limit / Quota)
        if "RESOURCE_EXHAUSTED" in err_str or "429" in err_str or "QUOTA" in err_str:
            wait_time = 20
            console.print(f"[yellow]  Rate limit (429 RESOURCE_EXHAUSTED) hit. Waiting {wait_time}s to cool down API quota...[/yellow]")
            return "retry", wait_time

        # 4. Check for 404 Not Found (Model not supported or not found)
        if "NOT_FOUND" in err_str or "404" in err_str or "NOT FOUND" in err_str:
            console.print("[yellow]  Model not found or not supported. Skipping this model...[/yellow]")
            return "skip_model", 0

        # 5. Default transient error (e.g. 500, 503)
        wait_time = (attempt + 1) * 5
        console.print(f"[red]  API Error: {str(e)[:200]}[/red]")
        console.print(f"[yellow]  Waiting {wait_time}s before retry...[/yellow]")
        return "retry", wait_time



    def _get_models(self, default_models: list[str]) -> list[str]:
        if not self.model:
            return default_models
        models = list(default_models)
        if self.model in models:
            models.remove(self.model)
        models.insert(0, self.model)
        return models



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
            focus_description = "buffer overflows, format string bugs, integer overflows, use-after-free, off-by-one errors, double-free, heap overflows, command injection, and panics/safety violations."
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
4. Generate up to {max_payloads} diverse payloads (safe to risk-inducing)."""

        from mutagen.models import FuzzPayloadList

        models_to_try = self._get_models(["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.5-flash", "gemini-2.5-pro"])
        response = None
        abort_outer = False
        for model_name in models_to_try:
            if abort_outer:
                break
            for attempt in range(3):
                try:
                    console.print(f"[dim]  Trying model: {model_name} (attempt {attempt + 1})...[/dim]")
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={
                            "temperature": 0.7,
                            "response_mime_type": "application/json",
                            "response_schema": FuzzPayloadList,
                            "safety_settings": [
                                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                            ],
                        },
                    )
                    break
                except Exception as e:
                    action, wait_time = self._classify_and_handle_error(e, attempt)
                    if action == "abort_all":
                        abort_outer = True
                        break
                    elif action == "skip_model":
                        break
                    elif action == "retry":
                        if wait_time > 0:
                            time.sleep(wait_time)

            if response is not None:
                break

        if response is None or response.text is None:
            console.print("[red]!! All models failed or response was empty/blocked. Check your API key or try again later.[/red]")
            return []

        raw = response.text.strip()
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- AI ANALYZE CODE RAW RESPONSE ---\n{raw}\n\n")
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "payloads" in data:
                return data["payloads"]
            elif isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            console.print("[red]!! Could not parse AI response as JSON.[/red]")
            console.print(f"[dim]First 300 chars: {raw[:300]}[/dim]")
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

Please analyze why the previous payload failed to cause a crash/safety violation.
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

        from mutagen.models import FuzzPayloadList
        models_to_try = self._get_models(["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.5-flash"])
        response = None
        abort_outer = False
        for model_name in models_to_try:
            if abort_outer:
                break
            for attempt in range(2):
                try:
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={
                            "temperature": 0.8,
                            "response_mime_type": "application/json",
                            "response_schema": FuzzPayloadList,
                            "safety_settings": [
                                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                            ],
                        },
                    )
                    break
                except Exception as e:
                    action, wait_time = self._classify_and_handle_error(e, attempt)
                    if action == "abort_all":
                        abort_outer = True
                        break
                    elif action == "skip_model":
                        break
                    elif action == "retry":
                        if wait_time > 0:
                            time.sleep(wait_time)
            if response is not None:
                break

        if response is None or response.text is None:
            return []

        raw = response.text.strip()
        if self.debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- AI REFINE PAYLOAD RAW RESPONSE ---\n{raw}\n\n")
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "payloads" in data:
                return data["payloads"]
            elif isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            return []

    def generate_patch(self, source_code: str, crash_data: dict, debug: bool = False) -> str:
        prompt = f"""You are a Senior {self.lang_name} Security Engineer.
An automated fuzzer just found a critical vulnerability in the following {self.lang_name} code.

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

REASONING:
{crash_data.get("reason")}

CRASH TYPE:
{crash_data.get("crash_type")}

Your task is to securely patch the vulnerability.
Provide the ENTIRE updated {self.lang_name} source code file that fixes the issue.
DO NOT use markdown formatting outside of the code block.
Return ONLY the raw {self.lang_name} code. DO NOT wrap it in ```{self.lang_ext} and ```.
If you must use markdown, the parser will try to strip it, but please try to return just the code."""

        models_to_try = self._get_models(["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.5-flash"])
        response = None
        abort_outer = False
        for model_name in models_to_try:
            if abort_outer:
                break
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
                    action, wait_time = self._classify_and_handle_error(e, attempt)
                    if action == "abort_all":
                        abort_outer = True
                        break
                    elif action == "skip_model":
                        break
                    elif action == "retry":
                        if wait_time > 0:
                            time.sleep(wait_time)
            if response is not None:
                break

        if response is None or response.text is None:
            return ""

        text = response.text.strip()
        for prefix in (f"```{self.lang_ext}", "```rust", "```c", "```"):
            if text.lower().startswith(prefix):
                text = text[len(prefix):]
                break
        if text.endswith("```"):
            text = text[:-3]

        return text.strip()

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
Return ONLY the raw {self.lang_name} code. DO NOT wrap it in ```{self.lang_ext} and ```.
If you must use markdown, the parser will try to strip it, but please try to return just the code."""

        models_to_try = self._get_models(["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.5-flash"])
        response = None
        abort_outer = False
        for model_name in models_to_try:
            if abort_outer:
                break
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
                    action, wait_time = self._classify_and_handle_error(e, attempt)
                    if action == "abort_all":
                        abort_outer = True
                        break
                    elif action == "skip_model":
                        break
                    elif action == "retry":
                        if wait_time > 0:
                            time.sleep(wait_time)
            if response is not None:
                break

        if response is None or response.text is None:
            return ""

        text = response.text.strip()
        for prefix in (f"```{self.lang_ext}", "```rust", "```c", "```"):
            if text.lower().startswith(prefix):
                text = text[len(prefix):]
                break
        if text.endswith("```"):
            text = text[:-3]

        return text.strip()

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

        models_to_try = self._get_models(["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.5-flash", "gemini-2.5-pro"])
        response = None
        abort_outer = False
        for model_name in models_to_try:
            if abort_outer:
                break
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
                    action, wait_time = self._classify_and_handle_error(e, attempt)
                    if action == "abort_all":
                        abort_outer = True
                        break
                    elif action == "skip_model":
                        break
                    elif action == "retry":
                        if wait_time > 0:
                            time.sleep(wait_time)
            if response is not None:
                break

        if response is None or response.text is None:
            return ""

        text = response.text.strip()
        if text.startswith("```python"):
            text = text[9:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]

        return text.strip()

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

        models_to_try = self._get_models(["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.5-flash", "gemini-2.5-pro"])
        response = None
        abort_outer = False
        for model_name in models_to_try:
            if abort_outer:
                break
            for attempt in range(2):
                try:
                    if debug:
                        console.print(f"[dim]  Deobfuscator trying model: {model_name}...[/dim]")
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
                    action, wait_time = self._classify_and_handle_error(e, attempt)
                    if action == "abort_all":
                        abort_outer = True
                        break
                    elif action == "skip_model":
                        break
                    elif action == "retry":
                        if wait_time > 0:
                            time.sleep(wait_time)
            if response is not None:
                break

        if response is None or response.text is None:
            return raw_code

        text = response.text.strip()
        if text.startswith("```c"):
            text = text[4:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]

        return text.strip()


