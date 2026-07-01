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
        self.client = OpenAI(api_key=self.api_key, timeout=60.0)

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

    def _parse_generate(self, prompt: str, response_model: type, list_key: str, system: str = "") -> list[dict]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        for attempt in range(3):
            try:
                response = self.client.beta.chat.completions.parse(
                    model=self.model,
                    messages=messages,
                    temperature=0.7,
                    response_format=response_model
                )
                parsed = response.choices[0].message.parsed
                if parsed is not None:
                    items = getattr(parsed, list_key, [])
                    return [item.model_dump() for item in items]
                return []
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
                    console.print(f"[yellow]  OpenAI Structured Output failed: {e}. Falling back to standard JSON mode...[/yellow]")
                    try:
                        fallback_prompt = prompt + f"\n\nRespond strictly with a JSON object containing a '{list_key}' key."
                        fallback_messages = []
                        if system:
                            fallback_messages.append({"role": "system", "content": system})
                        fallback_messages.append({"role": "user", "content": fallback_prompt})
                        
                        response = self.client.chat.completions.create(
                            model=self.model,
                            messages=fallback_messages,
                            temperature=0.7,
                            response_format={"type": "json_object"}
                        )
                        raw = response.choices[0].message.content.strip()
                        data = json.loads(raw)
                        if isinstance(data, dict) and list_key in data:
                            return data[list_key]
                        elif isinstance(data, list):
                            return data
                        elif isinstance(data, dict):
                            for k, v in data.items():
                                if isinstance(v, list):
                                    return v
                            return [data]
                        return []
                    except Exception as fallback_err:
                        console.print(f"[red]OpenAI JSON fallback failed: {fallback_err}[/red]")
                        return []
        return []

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
        if self.lang == "solidity":
            focus_description = "reentrancy (external call before state update), integer overflow/underflow, access control violations (e.g. tx.origin auth, missing modifiers), front-running/sandwich vectors, delegatecall to untrusted targets, and logical/state transition flaws."
        elif self.lang == "html":
            focus_description = "DOM-based Cross-Site Scripting (DOM XSS), unsafe script sourcing, missing security headers, clickjacking vulnerability, insecure sandbox iframe attributes, and client-side form vulnerabilities."
        elif self.lang == "javascript":
            focus_description = "Cross-Site Scripting (XSS), insecure eval/Function injection, client-side open redirects, hardcoded sensitive tokens/keys, insecure postMessage communications, insecure storage, and logical validation bypasses."
        elif self.lang == "css":
            focus_description = "CSS injection, data exfiltration via background url(http://...) and attribute selectors, and loading of malicious external stylesheets."
        elif profile == "supply-chain":
            focus_description = "unauthorized network calls, hardcoded backdoors, hidden command execution, environment variable exfiltration, and secrets/credential leaks."
        elif profile == "malware-triage":
            focus_description = "malware signatures, encryption algorithms (e.g., ransomware encryption loops), persistence mechanisms, keyloggers, evasion techniques, and command & control (C2) footprint."
        else:
            focus_description = "buffer overflows, format string bugs, integer overflows, use-after-free, off-by-one errors, double-free, heap overflows, and command injection."

        if self.lang == "solidity":
            guidelines = f"""Approach the audit step-by-step to identify high-impact logical exploits:
1. **Reentrancy**: Inspect functions executing external transfers or calling untrusted addresses before updating contract state variables. Ensure Checks-Effects-Interactions is broken to trigger reentrancy.
2. **Integer Safety**: Look for mathematical operations that can overflow/underflow, particularly in Solidity <0.8.0 without SafeMath, or inside unchecked blocks in newer compiler versions.
3. **Access Control & Trust Boundaries**: Trace critical administrative, withdrawal, or state-modifying actions. Look for reliance on tx.origin instead of msg.sender, missing onlyOwner or custom modifiers, or improper visibility settings.
4. **Economic & Front-running Vectors**: Examine slippage controls, sandwich attack opportunities, or block-timestamp manipulation vulnerabilities.
5. **Payload Design**: Construct function arguments (e.g. address values, array limits, uint magnitudes) that cause contract storage corruption, drain balances, or lock contract logic. Generate up to {max_payloads} highly creative transaction inputs."""
        elif self.lang == "html":
            guidelines = f"""Approach the audit step-by-step to identify front-end issues:
1. **DOM XSS Sources & Sinks**: Look for input parameters or URL hashes written straight to the DOM.
2. **Resource Integrity**: Inspect script sources. Check for missing Subresource Integrity (SRI) hashes on scripts from public CDNs.
3. **Security Directives**: Check for missing meta tag directives like Content Security Policy (CSP).
4. **IFrame Isolation**: Inspect iframes for missing sandbox flags."""
        elif self.lang == "javascript":
            guidelines = f"""Approach the audit step-by-step to identify script vulnerabilities:
1. **Injection Vectors**: Search for direct calls to `eval()`, `new Function()`, `setTimeout(string)`, or setting `element.innerHTML` using unsanitized user inputs.
2. **Secrets & Hardcoded Keys**: Audit the script for client-side API keys, credentials, or session tokens.
3. **Open Redirects**: Identify variables modifying `window.location` or `window.location.replace()` using untrusted inputs.
4. **Cross-Origin Security**: Check `window.addEventListener('message')` handlers to ensure they strictly validate the origin before processing payloads."""
        elif self.lang == "css":
            guidelines = f"""Approach the audit step-by-step to identify style issues:
1. **Attribute Exfiltration**: Identify background-image background urls tracking element attributes (e.g. input[value^="a"] {{ background-image: url(...) }}).
2. **External Imports**: Check for dangerous imports of unverified external stylesheets."""
        else:
            guidelines = f"""Approach the audit step-by-step to identify high-severity exploits:
1. **Attack Surface & Input Extraction**: Map all entry points, parsers, and bounds checks. Identify the exact format constraints (prefixes, headers, separators) the program expects.
2. **Data-Flow & Taint Tracking**: Trace user input from source to unsafe sinks (e.g., memcpy, strcpy, printf, free, array indexing). Check for unsafe type casts (signed/unsigned mismatches) or pointer arithmetic.
3. **Sanitization Bypass**: If checks (length limits, character filters) exist, design bypasses using null-byte injection, integer wrapping, double-free states, or character encoding variations.
4. **Memory/Logical Corruption**: Identify exact byte offsets or state sequences needed to overflow buffers, corrupt frame pointers, or trigger logic state machine transitions.
5. **No Placeholders**: Every payload must contain fully formed, functional exploit inputs. Do NOT use generic placeholder text (like "A" * 100). Construct precise byte arrays, format specifiers, or boundary inputs.
6. **Diversity**: Generate up to {max_payloads} highly creative, diverse payloads targeting different logical blocks or vulnerability classes."""


        prompt = f"""You are an elite, adversarial security researcher and exploit developer.
{decompile_context}
Your objective is to conduct a deep semantic and logical vulnerability audit of the following {self.lang_name} source code.
Focus on identifying security-critical bugs (such as {focus_description}) and generating targeted inputs to trigger them.

[INPUT DELIVERY METHOD]
The program receives input via: {delivery_mode}.
- If 'args', you must populate the "args" field with realistic command-line argument lists.
- If 'stdin' or 'tcp', you must populate the "input_data" field with raw payload data (e.g. buffer overflow strings, format string patterns, boundary values).

[SOURCE CODE]
```{self.lang_ext}
{source_code}
```

[AUDIT RULES & GUIDELINES]
{guidelines}
"""

        from mutagen.models import FuzzPayloadList
        payloads = self._parse_generate(prompt, FuzzPayloadList, "payloads", system="You are an automated code audit assistant.")
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- OpenAI ANALYZE CODE RAW RESPONSE ---\n{json.dumps(payloads, indent=2)}\n\n")
        return payloads


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
        import sys
        os_info = ""
        if sys.platform == "win32":
            os_info = "\nIMPORTANT: The patch will be compiled on Windows using MinGW GCC. Ensure the code is compatible with Windows/MinGW and does NOT use POSIX-specific headers/functions (like sys/wait.h, unistd.h, sigaction, sigprocmask, sigset_t, fork, pipe, etc.) unless there is a standard Windows alternative, or unless you can write standard, portable, cross-platform ISO C code."

        prompt = f"""You are a Senior {self.lang_name} Security Engineer. Securely patch this {self.lang_name} code:
{os_info}

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
        import sys
        os_info = ""
        if sys.platform == "win32":
            os_info = "\nIMPORTANT: The patch will be compiled on Windows using MinGW GCC. Ensure the code is compatible with Windows/MinGW and does NOT use POSIX-specific headers/functions (like sys/wait.h, unistd.h, sigaction, sigprocmask, sigset_t, fork, pipe, etc.) unless there is a standard Windows alternative, or unless you can write standard, portable, cross-platform ISO C code."

        prompt = f"""You are a Senior {self.lang_name} Security Engineer.
We tried to patch a vulnerability in the following {self.lang_name} code, but the patch failed.
{os_info}

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

    def generate_payloads(self, source_code: str, prompt: str, max_payloads: int, debug: bool = False) -> list[dict]:
        from mutagen.models import FuzzSequenceList
        full_prompt = f"{prompt}\n\nSOURCE CODE:\n```\n{source_code}\n```"
        sequences = self._parse_generate(full_prompt, FuzzSequenceList, "sequences", system="You are an automated code audit assistant.")
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- OpenAI GENERATE PAYLOADS RAW RESPONSE ---\n{json.dumps(sequences, indent=2)}\n\n")
        return sequences




