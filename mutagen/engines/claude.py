import os
import json
import time
from rich.console import Console
from mutagen.engines.base import BaseEngine

console = Console(force_terminal=True, force_jupyter=False)

class ClaudeEngine(BaseEngine):
    def __init__(self, api_key: str, model: str = ""):
        self.api_key = api_key
        self.model = model or "claude-3-5-sonnet-latest"
        from anthropic import Anthropic
        self.client = Anthropic(api_key=self.api_key)

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
        if profile == "supply-chain":
            focus_description = "unauthorized network calls, hardcoded backdoors, hidden command execution, environment variable exfiltration, and secrets/credential leaks."
            vuln_types_example = '"backdoor", "credential_leak", "command_injection"'
        elif profile == "malware-triage":
            focus_description = "malware signatures, encryption algorithms (e.g., ransomware encryption loops), persistence mechanisms, keyloggers, evasion techniques, and command & control (C2) footprint."
            vuln_types_example = '"malware_persistence", "ransomware_encryption", "keylogger_module"'
        else:
            focus_description = "potential memory/logical vulnerabilities (buffer overflows, format string bugs, integer overflows, use-after-free, double-free, command injection)."
            vuln_types_example = '"buffer_overflow", "format_string", "integer_overflow"'

        prompt = f"""{decompile_context}You are an audit security researcher. Analyze this C code for potential vulnerabilities and security risks, focusing on: {focus_description}
{source_code}

The program gets input via: {delivery_mode}.

Generate up to {max_payloads} diverse fuzzing payloads or risk indicator scenarios.
Respond with ONLY a JSON array of payloads containing:
- "args": array of strings (argv)
- "input_data": raw input string (stdin/network)
- "vuln_type": vuln/risk name string (e.g. {vuln_types_example})
- "reason": logic explanation string
- "severity": "critical"/"high"/"medium"/"low"
- "cwe": CWE ID string if known
- "data_flow": array of strings tracing execution flow from entry-point input (Source) to the vulnerability function/sink
- "confidence_score": integer from 1 to 10 assessing vulnerability trigger confidence
- "mitigations_detected": array of strings listing security checks/canaries/filters detected in the code path"""
        
        raw = self._generate(prompt, system="You are an automated code audit assistant. Respond only in raw JSON arrays.")
        if debug:
            with open("mutagen_debug.log", "a", encoding="utf-8") as f:
                f.write(f"--- Claude ANALYZE CODE RAW RESPONSE ---\n{raw}\n\n")
        return self._extract_json(raw)

    def refine_payload(self, source_code: str, failed_args: list[str], failed_input: str, stdout: str, stderr: str, return_code: int, delivery_mode: str) -> list[dict]:
        prompt = f"""You audit security vulnerabilities in C code.
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
        prompt = f"""Securely patch the vulnerability in this C code:
{source_code}

Vulnerability: {crash_data.get("vuln_type")}
Reason: {crash_data.get("reason")}
Args: {crash_data.get("args")}

Return the ENTIRE updated C source code file. Do not include markdown blocks, explanations, or backticks."""
        
        text = self._generate(prompt, system="You are a senior C developer. Output only the C code. No markup, no markdown formatting, no backticks, no comments outside C.")
        if text.startswith("```c"):
            text = text[4:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def refine_patch(self, source_code: str, bad_patch: str, error_message: str, crash_data: dict, debug: bool = False) -> str:
        prompt = f"""Correct the patch for this C code. The previous attempt failed.

ORIGINAL CODE:
{source_code}

ATTEMPTED PATCH THAT FAILED:
{bad_patch}

FAILURE DETAILS:
{error_message}

Vulnerability: {crash_data.get("vuln_type")}
Args: {crash_data.get("args")}

Return the ENTIRE corrected C source code file. Do not include markdown blocks, explanations, or backticks."""
        
        text = self._generate(prompt, system="You are a senior C developer. Output only the corrected C code. No markup, no markdown formatting, no backticks, no comments outside C.")
        if text.startswith("```c"):
            text = text[4:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, delivery_mode: str, debug: bool = False) -> str:
        prompt = f"""Write a Python 3 script replicating the crash in '{exe_path}' (delivery via '{delivery_mode}').
C Source:
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

