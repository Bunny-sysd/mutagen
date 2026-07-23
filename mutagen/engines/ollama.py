import json

from rich.console import Console

from mutagen.engines.base import BaseEngine

console = Console(force_terminal=True, force_jupyter=False)

class OllamaEngine(BaseEngine):
    def __init__(self, model: str = "", debug: bool = False):
        import os
        self.debug = debug
        self.model = model or os.environ.get("MUTAGEN_MODEL", "llama3.2")
        import requests
        self.requests = requests

        # Get standard MUTAGEN_OLLAMA_URL or fall back to constructing it from OLLAMA_HOST
        env_url = os.environ.get("MUTAGEN_OLLAMA_URL", "")
        if not env_url:
            env_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434").strip()

        urls = []
        if "," in env_url:
            raw_urls = env_url.split(",")
            for raw_url in raw_urls:
                raw_url = raw_url.strip()
                if not raw_url:
                    continue
                if ":" in raw_url and not raw_url.startswith("http"):
                    raw_url = f"http://{raw_url}"
                elif not raw_url.startswith("http"):
                    raw_url = f"http://{raw_url}"

                if not raw_url.endswith("/api/generate"):
                    raw_url = f"{raw_url.rstrip('/')}/api/generate"
                urls.append(raw_url)
        else:
            if ":" in env_url and not env_url.startswith("http"):
                env_url = f"http://{env_url}"
            elif not env_url.startswith("http"):
                env_url = f"http://{env_url}"

            if not env_url.endswith("/api/generate"):
                env_url = f"{env_url.rstrip('/')}/api/generate"
            urls = [env_url]

        from mutagen.swarm_balancer import SwarmBalancer
        self.balancer = SwarmBalancer(urls)
        self.url = urls[0] if urls else "http://localhost:11434/api/generate"

    def _generate(self, prompt: str, system: str = "", format_json: bool = False, response_schema: dict = None) -> str:
        import os
        try:
            num_ctx = int(os.environ.get("MUTAGEN_OLLAMA_NUM_CTX", "8192"))
        except ValueError:
            num_ctx = 8192

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": num_ctx
            }
        }
        if system:
            payload["system"] = system
        if response_schema:
            payload["format"] = response_schema
        elif format_json:
            payload["format"] = "json"

        url = self.balancer.get_next_node() if hasattr(self, "balancer") else self.url
        try:
            response = self.requests.post(url, json=payload, timeout=180)
            if response.status_code == 200:
                return response.json().get("response", "").strip()
            else:
                console.print(f"[red]Ollama error: HTTP {response.status_code}[/red]")
                return ""
        except Exception as e:
            console.print(f"[red]Ollama connection failed: {e}[/red]")
            return ""

    def _parse_payload_list(self, raw: str) -> list[dict]:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        if all(isinstance(x, dict) for x in v):
                            return v
                return [data] if all(isinstance(v, str) for v in data.keys()) else []
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]
            return []
        except Exception:
            return []

    def analyze_code(self, source_code: str, max_payloads: int, delivery_mode: str, debug: bool, profile: str = "legacy-audit") -> list[dict]:
        decompile_context = ""
        if getattr(self, "is_decompiled", False):
            decompile_context = (
                "CRITICAL CONTEXT: This is DECOMPILED pseudo-C code extracted from a compiled binary via Ghidra. "
                "Variable names are auto-generated (e.g., param_1, iVar2). "
                "Focus on security patterns: buffer operations, pointer arithmetic, unsafe casts.\n\n"
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
            focus_description = "buffer overflows, format string bugs, integer overflows, use-after-free, panics, etc."

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
        raw = self._generate(prompt, system="You are an automated code audit assistant.", response_schema=FuzzPayloadList.model_json_schema())
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- Ollama ANALYZE CODE RAW RESPONSE ---\n{raw}\n\n")
        parsed = self._parse_payload_list(raw)
        if not parsed and raw:
            console.print(f"[red]Failed to parse Ollama JSON: {raw[:300]}[/red]")
        return parsed


    def refine_payload(self, source_code: str, failed_args: list[str], failed_input: str, stdout: str, stderr: str, return_code: int, delivery_mode: str) -> list[dict]:
        prompt = f"""We are fuzzing this {self.lang_name} code where input is delivered via {delivery_mode}:
{source_code}

Previous attempt details:
- Args: {failed_args}
- Input data: {failed_input}
- Exit code was: {return_code}
- Stdout: {stdout}
- Stderr: {stderr}

Generate 2-3 refined payloads in a JSON list (containing both "args" and "input_data" fields) to bypass validation or cause a crash/panic."""
        raw = self._generate(prompt, format_json=True)
        return self._parse_payload_list(raw)

    def generate_patch(self, source_code: str, crash_data: dict, debug: bool = False) -> str:
        import sys
        os_info = ""
        if sys.platform == "win32":
            os_info = "\nIMPORTANT: The patch will be compiled on Windows using MinGW GCC. Ensure the code is compatible with Windows/MinGW and does NOT use POSIX-specific headers/functions (like sys/wait.h, unistd.h, sigaction, sigprocmask, sigset_t, fork, pipe, etc.) unless there is a standard Windows alternative, or unless you can write standard, portable, cross-platform ISO C code."

        prompt = f"""Securely patch the vulnerability in this {self.lang_name} code:
{os_info}

{source_code}

Vulnerability: {crash_data.get("vuln_type")}
Args: {crash_data.get("args")}

Return only the updated {self.lang_name} source code file. Do not include markdown blocks, explanations, or backticks."""
        text = self._generate(prompt)
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

        prompt = f"""We tried to patch a vulnerability in the following {self.lang_name} code, but the patch failed.
{os_info}

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
Provide the ENTIRE corrected {self.lang_name} source code file.
DO NOT use markdown formatting outside of the code block.
Return ONLY the raw {self.lang_name} code. DO NOT wrap it in ```{self.lang_ext} and ```."""
        text = self._generate(prompt)
        for prefix in (f"```{self.lang_ext}", "```rust", "```c", "```"):
            if text.lower().startswith(prefix):
                text = text[len(prefix):]
                break
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, delivery_mode: str, debug: bool = False) -> str:
        prompt = f"""Write a standalone Python 3 script reproducing the crash in '{exe_path}' where input delivery is via '{delivery_mode}'.
{self.lang_name} Code:
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
        text = self._generate(prompt)
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
        raw = self._generate(full_prompt, system="You are an automated code audit assistant.", response_schema=FuzzSequenceList.model_json_schema())
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- Ollama GENERATE PAYLOADS RAW RESPONSE ---\n{raw}\n\n")
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "sequences" in data:
                return data["sequences"]
            elif isinstance(data, list):
                return data
            return []
        except Exception:
            return []



