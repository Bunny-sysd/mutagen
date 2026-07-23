import json
import time

from rich.console import Console

from mutagen.engines.base import BaseEngine

console = Console(force_terminal=True, force_jupyter=False)

class ClaudeEngine(BaseEngine):
    def __init__(self, api_key: str, model: str = "", debug: bool = False):
        self.api_key = api_key
        self.model = model or "claude-3-5-sonnet-latest"
        self.debug = debug
        from anthropic import Anthropic
        self.client = Anthropic(api_key=self.api_key, timeout=60.0)

    def _generate(self, prompt: str, system: str = "") -> str:
        kwargs = {
            "model": self.model,
            "max_tokens": 4000,
            "temperature": 0.2,
            "messages": [{"role": "user", "content": prompt}]
        }
        if system:
            kwargs["system"] = system

        for attempt in range(3):
            try:
                message = self.client.messages.create(**kwargs)
                return message.content[0].text.strip()
            except Exception as e:
                err_str = str(e).lower()
                if "rate limit" in err_str or "429" in err_str or "quota" in err_str:
                    wait_time = 20
                    console.print(f"[yellow]  Rate limit (429) hit on Claude. Waiting {wait_time}s to cool down...[/yellow]")
                    time.sleep(wait_time)
                elif "500" in err_str or "503" in err_str or "timeout" in err_str:
                    wait_time = (attempt + 1) * 5
                    console.print(f"[yellow]  Claude transient error. Waiting {wait_time}s before retry...[/yellow]")
                    time.sleep(wait_time)
                else:
                    console.print(f"[red]Claude API error: {e}[/red]")
                    return ""
        console.print("[red]Claude API failed after multiple retries.[/red]")
        return ""

    def _parse_generate(self, prompt: str, response_model: type, list_key: str, system: str = "") -> list[dict]:
        kwargs = {
            "model": self.model,
            "max_tokens": 4000,
            "temperature": 0.2,
            "messages": [{"role": "user", "content": prompt}],
            "response_model": response_model,
            "betas": ["structured-outputs-2025-11-13"]
        }
        if system:
            kwargs["system"] = system

        for attempt in range(3):
            try:
                message = self.client.beta.messages.parse(**kwargs)
                parsed = message.parsed
                if parsed is not None:
                    items = getattr(parsed, list_key, [])
                    return [item.model_dump() for item in items]
                return []
            except Exception as e:
                err_str = str(e).lower()
                if "rate limit" in err_str or "429" in err_str or "quota" in err_str:
                    wait_time = 20
                    console.print(f"[yellow]  Rate limit (429) hit on Claude. Waiting {wait_time}s to cool down...[/yellow]")
                    time.sleep(wait_time)
                elif "500" in err_str or "503" in err_str or "timeout" in err_str:
                    wait_time = (attempt + 1) * 5
                    console.print(f"[yellow]  Claude transient error. Waiting {wait_time}s before retry...[/yellow]")
                    time.sleep(wait_time)
                else:
                    console.print(f"[yellow]  Claude Structured Output failed: {e}. Falling back to standard JSON mode...[/yellow]")
                    try:
                        fallback_prompt = prompt + f"\n\nRespond strictly with a JSON object containing a '{list_key}' key."
                        sys_prompt = system + " Respond only in raw JSON."
                        raw = self._generate(fallback_prompt, system=sys_prompt)
                        return self._extract_json(raw)
                    except Exception as fallback_err:
                        console.print(f"[red]Claude JSON fallback failed: {fallback_err}[/red]")
                        return []
        return []

    def _extract_json(self, text: str) -> list[dict]:
        text = text.strip()
        if "```json" in text:
            try:
                parts = text.split("```json")
                block = parts[1].split("```")[0].strip()
                return json.loads(block)
            except Exception:
                pass
        if "```" in text:
            try:
                parts = text.split("```")
                block = parts[1].strip()
                return json.loads(block)
            except Exception:
                pass
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        return v
                return [data]
            return data
        except Exception:
            return []

    def analyze_code(self, source_code: str, max_payloads: int, delivery_mode: str, debug: bool, profile: str = "legacy-audit") -> list[dict]:
        decompile_context = ""
        if getattr(self, "is_decompiled", False):
            decompile_context = (
                "CRITICAL CONTEXT: This is DECOMPILED pseudo-C code from a binary (Ghidra). "
                "Variable names are auto-generated. Focus on security patterns.\n\n"
            )
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
            focus_description = "potential memory/logical vulnerabilities (buffer overflows, format string bugs, integer overflows, use-after-free, double-free, command injection)."

        if self.lang == "solidity":
            guidelines = f"""Approach the audit step-by-step to identify high-impact logical exploits:
1. **Reentrancy**: Inspect functions executing external transfers or calling untrusted addresses before updating contract state variables. Ensure Checks-Effects-Interactions is broken to trigger reentrancy.
2. **Integer Safety**: Look for mathematical operations that can overflow/underflow, particularly in Solidity <0.8.0 without SafeMath, or inside unchecked blocks in newer compiler versions.
3. **Access Control & Trust Boundaries**: Trace critical administrative, withdrawal, or state-modifying actions. Look for reliance on tx.origin instead of msg.sender, missing onlyOwner or custom modifiers, or improper visibility settings.
4. **Economic & Front-running Vectors**: Examine slippage controls, sandwich attack opportunities, or block-timestamp manipulation vulnerabilities.
5. **Payload Design**: Construct function arguments (e.g. address values, array limits, uint magnitudes) that cause contract storage corruption, drain balances, or lock contract logic. Generate up to {max_payloads} highly creative transaction inputs."""
        elif self.lang == "html":
            guidelines = """Approach the audit step-by-step to identify front-end issues:
1. **DOM XSS Sources & Sinks**: Look for input parameters or URL hashes written straight to the DOM.
2. **Resource Integrity**: Inspect script sources. Check for missing Subresource Integrity (SRI) hashes on scripts from public CDNs.
3. **Security Directives**: Check for missing meta tag directives like Content Security Policy (CSP).
4. **IFrame Isolation**: Inspect iframes for missing sandbox flags."""
        elif self.lang == "javascript":
            guidelines = """Approach the audit step-by-step to identify script vulnerabilities:
1. **Injection Vectors**: Search for direct calls to `eval()`, `new Function()`, `setTimeout(string)`, or setting `element.innerHTML` using unsanitized user inputs.
2. **Secrets & Hardcoded Keys**: Audit the script for client-side API keys, credentials, or session tokens.
3. **Open Redirects**: Identify variables modifying `window.location` or `window.location.replace()` using untrusted inputs.
4. **Cross-Origin Security**: Check `window.addEventListener('message')` handlers to ensure they strictly validate the origin before processing payloads."""
        elif self.lang == "css":
            guidelines = """Approach the audit step-by-step to identify style issues:
1. **Attribute Exfiltration**: Identify background-image background urls tracking element attributes (e.g. input[value^="a"] { background-image: url(...) }).
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
```
{source_code}
```

[AUDIT RULES & GUIDELINES]
{guidelines}
"""

        from mutagen.models import FuzzPayloadList
        payloads = self._parse_generate(prompt, FuzzPayloadList, "payloads", system="You are an automated code audit assistant.")
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- Claude ANALYZE CODE RAW RESPONSE ---\n{json.dumps(payloads, indent=2)}\n\n")
        return payloads



    def refine_payload(self, source_code: str, failed_args: list[str], failed_input: str, stdout: str, stderr: str, return_code: int, delivery_mode: str) -> list[dict]:
        prompt = f"""You audit security vulnerabilities in {self.lang_name} code.
A previous payload did not crash the target. Refine it to trigger the bug.

SOURCE CODE:
{source_code}

FAILED PAYLOAD:
- Args: {failed_args}
- Input: {failed_input}

EXECUTION METRICS:
- Return code: {return_code}
- stdout: {stdout}
- stderr: {stderr}

Generate 2-3 new, refined payloads.
Respond ONLY with a valid JSON array matching the original schema. No extra words."""

        raw = self._generate(prompt, system="You are an automated payload refinement assistant. Respond only in raw JSON arrays.")
        return self._extract_json(raw)

    def generate_patch(self, source_code: str, crash_data: dict, debug: bool = False) -> str:
        import sys
        os_info = ""
        if sys.platform == "win32":
            os_info = "\nIMPORTANT: The patch will be compiled on Windows using MinGW GCC. Ensure the code is compatible with Windows/MinGW and does NOT use POSIX-specific headers/functions (like sys/wait.h, unistd.h, sigaction, sigprocmask, sigset_t, fork, pipe, etc.) unless there is a standard Windows alternative, or unless you can write standard, portable, cross-platform ISO C code."

        prompt = f"""Securely patch the vulnerability in this {self.lang_name} code:
{os_info}

{source_code}

Vulnerability: {crash_data.get("vuln_type")}
Reason: {crash_data.get("reason")}
Args: {crash_data.get("args")}

Return the ENTIRE updated {self.lang_name} source code file. Do not include markdown blocks, explanations, or backticks."""

        text = self._generate(prompt, system=f"You are a senior {self.lang_name} developer. Output only the {self.lang_name} code. No markup, no markdown formatting, no backticks, no comments outside {self.lang_name}.")
        for prefix in (f"```{self.lang_ext}", "```rust", "```c", "```"):
            if text.lower().startswith(prefix):
                text = text[len(prefix):]
                break
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def refine_patch(self, source_code: str, bad_patch: str, error_message: str, crash_data: dict, debug: bool = False) -> str:
        import sys
        os_info = ""
        if sys.platform == "win32":
            os_info = "\nIMPORTANT: The patch will be compiled on Windows using MinGW GCC. Ensure the code is compatible with Windows/MinGW and does NOT use POSIX-specific headers/functions (like sys/wait.h, unistd.h, sigaction, sigprocmask, sigset_t, fork, pipe, etc.) unless there is a standard Windows alternative, or unless you can write standard, portable, cross-platform ISO C code."

        prompt = f"""Correct the patch for this {self.lang_name} code. The previous attempt failed.
{os_info}

ORIGINAL CODE:
{source_code}

ATTEMPTED PATCH THAT FAILED:
{bad_patch}

FAILURE DETAILS:
{error_message}

Vulnerability: {crash_data.get("vuln_type")}
Args: {crash_data.get("args")}

Return the ENTIRE corrected {self.lang_name} source code file. Do not include markdown blocks, explanations, or backticks."""

        text = self._generate(prompt, system=f"You are a senior {self.lang_name} developer. Output only the corrected {self.lang_name} code. No markup, no markdown formatting, no backticks, no comments outside {self.lang_name}.")
        for prefix in (f"```{self.lang_ext}", "```rust", "```c", "```"):
            if text.lower().startswith(prefix):
                text = text[len(prefix):]
                break
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, delivery_mode: str, debug: bool = False) -> str:
        prompt = f"""Write a Python 3 script replicating the crash in '{exe_path}' (delivery via '{delivery_mode}').
{self.lang_name} Source:
{source_code}

Crash payload:
- Args: {crash_data.get("args")}
- Input: {crash_data.get("input_data")}

The script must accept target exe as sys.argv[1] (defaulting to '{exe_path}').
Return ONLY python code. No explanations, no markdown blocks, no backticks."""

        text = self._generate(prompt, system="You are a security QA developer. Output only raw Python code.")
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
6. Return ONLY raw C code. DO NOT wrap it in ```c and ```. No explanations outside of the code block.

RAW DECOMPILED PSEUDO-CODE:
{raw_code}

Return ONLY the refactored, commented, and readable C code."""
        text = self._generate(prompt, system="You are an expert reverse engineer. Output only raw refactored C code.")
        if text.startswith("```c"):
            text = text[4:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip() or raw_code

    def generate_payloads(self, source_code: str, prompt: str, max_payloads: int, debug: bool = False) -> list[dict]:
        from mutagen.models import FuzzSequenceList
        full_prompt = f"{prompt}\n\nSOURCE CODE:\n```\n{source_code}\n```"
        sequences = self._parse_generate(full_prompt, FuzzSequenceList, "sequences", system="You are an automated code audit assistant.")
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- Claude GENERATE PAYLOADS RAW RESPONSE ---\n{json.dumps(sequences, indent=2)}\n\n")
        return sequences




