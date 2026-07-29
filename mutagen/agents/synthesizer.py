import json
import struct

from pydantic import BaseModel, Field

from mutagen.agents.base import BaseAgent
from mutagen.agents.prompts import get_synthesizer_rules
from mutagen.engines import get_engine
from mutagen.poc_finder import get_cwe_poc_intelligence
from mutagen.safety import GEMINI_SAFETY_OFF
from mutagen.state import CrashPayload, ProgramContext


class PayloadList(BaseModel):
    class PayloadItem(BaseModel):
        args: list[str] = Field(default_factory=list)
        input_data: str = ""
        raw_bytes_hex: str | None = None
        reason: str = ""
    payloads: list[PayloadItem]

def robust_json_parse(raw: str) -> dict:
    """Sanitizes raw LLM output, strips markdown, handles unescaped characters, and uses regex/dict fallbacks."""
    if not raw or not raw.strip():
        return {"payloads": [{"args": [], "input_data": "", "raw_bytes_hex": None, "reason": "Fallback due to empty response"}]}

    cleaned = raw.strip()
    # Strip markdown block wrappers (```json ... ``` or ``` ...)
    if cleaned.startswith("```"):
        parts = cleaned.split("```")
        cleaned = parts[1] if len(parts) > 1 else cleaned
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()

    # Attempt 1: Direct json.loads
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # Attempt 2: Strict=False for raw newlines/tabs inside string literals
    try:
        data = json.loads(cleaned, strict=False)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # Attempt 3: Regex match for outermost JSON object { ... }
    import re
    match = re.search(r'\{.*\}', cleaned, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0), strict=False)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    # Fallback default dict — generate format-aware binary payloads for file mode
    return {"payloads": [{"args": [], "input_data": "", "raw_bytes_hex": None, "reason": "Fallback due to JSON parse error"}]}


def _generate_file_mode_fallback_payloads() -> list[dict]:
    """Generate format-aware binary fallback payloads for file-based targets.
    These cover common binary parser inputs (PNG, JPEG, ELF, PDF, ZIP, raw fuzz)
    so that even without AI payloads, the fuzzer has a real chance of triggering
    crashes in file-parsing code paths."""
    payloads = []

    # 1. Minimal PNG with corrupted IHDR (oversized dimensions trigger integer overflow)
    png_sig = b'\x89PNG\r\n\x1a\n'
    # IHDR: width=0xFFFFFFFF, height=0xFFFFFFFF, bit_depth=8, color_type=2
    ihdr_data = struct.pack('>II', 0xFFFFFFFF, 0xFFFFFFFF) + b'\x08\x02\x00\x00\x00'
    ihdr_chunk = struct.pack('>I', len(ihdr_data)) + b'IHDR' + ihdr_data
    png_payload = png_sig + ihdr_chunk
    payloads.append({
        "args": [], "input_data": "",
        "raw_bytes_hex": png_payload.hex(),
        "reason": "Fallback: corrupted PNG with 0xFFFFFFFF dimensions (integer overflow)"
    })

    # 2. Minimal PNG with zero-length IDAT (triggers allocation edge cases)
    idat_chunk = struct.pack('>I', 0) + b'IDAT'
    iend_chunk = struct.pack('>I', 0) + b'IEND'
    png_zero = png_sig + ihdr_chunk + idat_chunk + iend_chunk
    payloads.append({
        "args": [], "input_data": "",
        "raw_bytes_hex": png_zero.hex(),
        "reason": "Fallback: PNG with zero-length IDAT chunk (allocation edge case)"
    })

    # 3. Truncated file (just PNG signature, no chunks — triggers out-of-bounds read)
    payloads.append({
        "args": [], "input_data": "",
        "raw_bytes_hex": png_sig.hex(),
        "reason": "Fallback: truncated PNG signature only (OOB read)"
    })

    # 4. Large repetitive buffer (classic heap spray / overflow trigger)
    payloads.append({
        "args": [], "input_data": "",
        "raw_bytes_hex": (b'A' * 8192).hex(),
        "reason": "Fallback: 8KB buffer overflow probe"
    })

    # 5. Null bytes interspersed (triggers null-termination assumptions)
    payloads.append({
        "args": [], "input_data": "",
        "raw_bytes_hex": (b'\x00' * 256 + b'\xff' * 256).hex(),
        "reason": "Fallback: null byte + 0xFF block (boundary probe)"
    })

    return payloads


class PayloadSynthesizerAgent(BaseAgent):
    def __init__(self, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", api_key: str = None):
        super().__init__("Payload Synthesizer Agent", model_provider, model_name, api_key)
        self.engine = get_engine(model_provider, self.api_key, model_name)

    async def process(self, context: ProgramContext) -> ProgramContext:
        self.engine.language = context.language
        context.logs.append("[PayloadSynthesizerAgent] Synthesizing exploit payloads based on triage...")

        if not context.vulnerabilities:
            context.logs.append("[PayloadSynthesizerAgent] No vulnerabilities to synthesize payloads for.")
            return context

        # Query GitHub PoC Intelligence for real-world exploit snippets
        poc_hints = []
        for v in context.vulnerabilities[:2]:
            intel = get_cwe_poc_intelligence(v.cwe, v.vuln_type)
            for poc in intel.get("github_pocs", []):
                poc_str = f"GitHub PoC ({poc['name']}): {poc['url']} - {poc['description']}"
                poc_hints.append(poc_str)
                context.notepad.append(f"[Intelligence] {poc_str}")

        vuln_descriptions = [
            f"- {v.vuln_type} at line {v.line_number} ({v.cwe}): {v.metadata.get('reason', '')}"
            for v in context.vulnerabilities
        ]

        joined_vuln_desc = "\n".join(vuln_descriptions)
        lang_rules = get_synthesizer_rules(context.language)
        poc_context_str = ("\nReal-World GitHub PoC Intelligence:\n" + "\n".join(poc_hints)) if poc_hints else ""

        prompt = f"""You are an elite offensive security researcher and exploit developer.
Target System Platform: {context.os_platform} (Language: {context.language}, Delivery Mode: {context.delivery_mode})
Your objective is to generate exact crash/exploit payloads to reproduce the identified security flaws.

Vulnerabilities found:
{joined_vuln_desc}
{poc_context_str}

Source Code:
{context.source_code}

RULES:
1. Provide argument arrays, raw text/hex byte buffers, or structured input data to trigger the crash.
2. IMPORTANT: Keep all input data and argument strings under 1000 characters. Use short inputs that demonstrate the logic flow.
3. DO NOT prepend the program/target executable name to the 'args' list.
4. For 'file' delivery mode, provide raw structured bytes in 'input_data' or as a hex string in 'raw_bytes_hex' (e.g., "41414141...").
5. For logical vulnerabilities (like command injection), synthesize payloads that execute commands echoing known success strings (e.g., "echo vuln_triggered", "echo exploit_success", or "echo PWNED") or calling system status commands (e.g., "whoami", "id", or "systeminfo").
{lang_rules}
7. Return the results matching the requested JSON schema.
"""

        try:
            if self.model_provider == "gemini" and hasattr(self.engine, "client") and hasattr(self.engine.client, "models"):
                response = self.engine.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config={
                        "temperature": 0.5,
                        "response_mime_type": "application/json",
                        "response_schema": PayloadList,
                        "safety_settings": GEMINI_SAFETY_OFF,
                    }
                )
                raw_response_text = response.text
                # Diagnostic: log raw API response length for debugging empty/blocked responses
                if not raw_response_text or not raw_response_text.strip():
                    context.logs.append("[PayloadSynthesizerAgent] WARNING: Gemini API returned empty response (possible safety block or rate limit).")
                    if context.delivery_mode == "file":
                        context.logs.append("[PayloadSynthesizerAgent] Activating format-aware file mode fallback payloads...")
                        data = {"payloads": _generate_file_mode_fallback_payloads()}
                    else:
                        data = robust_json_parse(raw_response_text)
                else:
                    data = robust_json_parse(raw_response_text)
            else:
                # Multi-provider fallback for OpenAI, Claude, and Ollama
                raw_payloads = self.engine.generate_payloads(context.source_code, prompt, max_payloads=5, debug=False)
                payload_items = []
                for item in raw_payloads:
                    if isinstance(item, dict):
                        payload_items.append({
                            "args": item.get("args", []),
                            "input_data": item.get("input_data", ""),
                            "raw_bytes_hex": item.get("raw_bytes_hex"),
                            "reason": item.get("reason", "Synthesized by AI swarm")
                        })
                    elif isinstance(item, str):
                        payload_items.append({
                            "args": [item],
                            "input_data": item,
                            "raw_bytes_hex": None,
                            "reason": "Synthesized string payload"
                        })
                data = {"payloads": payload_items}

            payloads = data.get("payloads", [])
            for p in payloads:
                args = p.get("args", [])
                input_data = p.get("input_data", "")
                raw_bytes_hex = p.get("raw_bytes_hex")
                reason = p.get("reason", "")

                crash_payload = CrashPayload(
                    args=args,
                    input_data=input_data,
                    raw_bytes_hex=raw_bytes_hex
                )
                context.active_payloads.append(crash_payload)
                context.logs.append(f"[PayloadSynthesizerAgent] Generated payload args: {args} (Reason: {reason})")

        except Exception as e:
            context.logs.append(f"[PayloadSynthesizerAgent] Error generating payloads: {e}")
            # Fallback payload
            context.active_payloads.append(CrashPayload(args=[], input_data="", reason="Fallback due to execution error"))
            context.logs.append("[PayloadSynthesizerAgent] Added safe fallback payload")

        return context
