import json
import time
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

    def _generate(self, prompt: str, system: str = "", format_json: bool = False) -> str:
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
        if format_json:
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
        if profile == "supply-chain":
            focus_description = "unauthorized network calls, hardcoded backdoors, hidden command execution, environment variable exfiltration, and secrets/credential leaks."
            vuln_types_example = '"backdoor", "credential_leak", "command_injection"'
        elif profile == "malware-triage":
            focus_description = "malware signatures, encryption algorithms (e.g., ransomware encryption loops), persistence mechanisms, keyloggers, evasion techniques, and command & control (C2) footprint."
            vuln_types_example = '"malware_persistence", "ransomware_encryption", "keylogger_module"'
        else:
            focus_description = "buffer overflows, format string bugs, integer overflows, use-after-free, panics, etc."
            vuln_types_example = '"buffer_overflow", "format_string", "integer_overflow"'

        prompt = f"""{decompile_context}Analyze this {self.lang_name} source code for potential vulnerabilities and security risks, focusing on: {focus_description}
The target program receives input via: {delivery_mode}.

SOURCE CODE:
{source_code}

Format output as a JSON array of objects.
Each object must have these fields:
- "args": array of strings (used if delivery mode is 'args')
- "input_data": string containing raw input data (used if delivery mode is 'stdin' or 'tcp')
- "vuln_type": string (e.g., {vuln_types_example})
- "reason": string (explanation)
- "severity": "critical", "high", "medium", or "low"
- "cwe": string (CWE ID)
- "data_flow": array of strings tracing execution flow from entry-point input (Source) to the vulnerability function/sink
- "confidence_score": integer from 1 to 10 assessing vulnerability trigger confidence
- "mitigations_detected": array of strings listing security checks/canaries/filters detected in the code path

Generate up to {max_payloads} payloads. Study the entry point (main() or fn main()) for how input is read."""
        raw = self._generate(prompt, format_json=True)
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
        prompt = f"""Securely patch the vulnerability in this {self.lang_name} code:
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
        prompt = f"""We tried to patch a vulnerability in the following {self.lang_name} code, but the patch failed.

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

