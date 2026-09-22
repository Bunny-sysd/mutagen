import json
import re

from pydantic import BaseModel, Field

from mutagen.agents.base import BaseAgent
from mutagen.agents.prompts import get_synthesizer_rules
from mutagen.binary_repair import (
    MAGIC_ELF,
    MAGIC_GIF,
    MAGIC_GZ,
    MAGIC_JPEG,
    MAGIC_PNG,
    MAGIC_RIFF,
    MAGIC_SQLITE,
    MAGIC_ZIP,
    repair_binary_payload,
)
from mutagen.constants import (
    DEFAULT_GEMINI_FALLBACK_MODELS,
    DEFAULT_MODEL_GEMINI,
    DEFAULT_PROVIDER,
    SYNTHESIZER_TEMPERATURE,
)
from mutagen.engines import get_engine
from mutagen.safety import GEMINI_SAFETY_OFF
from mutagen.state import ProgramContext


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

    # Fallback default dict -- empty payload, discarded downstream by the
    # empty-payload check rather than filled in with hardcoded content
    return {"payloads": [{"args": [], "input_data": "", "raw_bytes_hex": None, "reason": "Fallback due to JSON parse error"}]}


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


# Real magic bytes per detected extension, used to give the synthesis prompt a
# format-appropriate example instead of always showing PNG's -- reused directly
# from binary_repair.py so the example always matches what repair_binary_payload
# actually recognizes for that format.
_EXAMPLE_MAGIC_BY_EXT: dict[str, bytes] = {
    ".png": MAGIC_PNG,
    ".jpg": MAGIC_JPEG,
    ".jpeg": MAGIC_JPEG,
    ".gif": MAGIC_GIF,
    ".zip": MAGIC_ZIP,
    ".gz": MAGIC_GZ,
    ".db": MAGIC_SQLITE,
    ".wav": MAGIC_RIFF,
    ".webp": MAGIC_RIFF,
    ".elf": MAGIC_ELF,
}

# Format-specific structural guidance for the synthesis prompt, keyed by detected
# extension. Only the format actually detected for THIS target is shown to the
# AI -- previously every target's prompt always showed PNG chunk names (IHDR,
# PLTE, IDAT) as the sole worked example, which could anchor payload synthesis
# toward PNG-shaped output even for targets with nothing to do with PNG.
_FORMAT_GUIDANCE_BY_EXT: dict[str, str] = {
    ".png": "This target parses PNG: construct structurally valid chunks (IHDR, PLTE, IDAT, IEND) with correct chunk lengths and CRC32 checksums, placing the boundary trigger inside chunk data so the parser processes it deeply.",
    ".jpg": "This target parses JPEG: construct a valid SOI marker and segment structure with correct segment length fields, placing the boundary trigger inside segment data.",
    ".jpeg": "This target parses JPEG: construct a valid SOI marker and segment structure with correct segment length fields, placing the boundary trigger inside segment data.",
    ".gif": "This target parses GIF: construct a valid GIF87a/GIF89a header and logical screen descriptor, placing the boundary trigger inside image/color-table data.",
    ".zip": "This target parses ZIP: construct a valid local file header (and matching Central Directory entry) with correct CRC32/size fields, placing the boundary trigger inside entry data.",
    ".elf": "This target parses ELF: construct a valid ELF header (correct magic, class, and endianness fields) with the boundary trigger in section/segment data.",
    ".db": "This target parses SQLite: construct a valid 16-byte SQLite header, placing the boundary trigger in page data.",
    ".wav": "This target parses RIFF/WAV: construct a valid RIFF header with a correct outer size field, placing the boundary trigger inside chunk data.",
    ".pdf": "This target parses PDF: construct a valid PDF header/trailer/xref structure, placing the boundary trigger inside a stream or object value.",
    ".json": "This target parses JSON: construct syntactically valid JSON, placing the boundary trigger in a string/number value or via deep nesting.",
    ".xml": "This target parses XML: construct well-formed XML, placing the boundary trigger in an attribute/element value or entity definition.",
}
_DEFAULT_FORMAT_GUIDANCE = "Construct a structurally valid file for this target's actual format (correct magic bytes, header fields, and any length/checksum fields the parser validates before reaching the vulnerable code), placing the boundary trigger inside the data fields so the parser processes the test case deeply."


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

        # Detect this target's actual format once, up front, so the prompt's own
        # example and structural guidance match THIS target instead of always
        # showing PNG -- computed once here and reused below rather than
        # recomputed from the same inputs multiple times later in this method.
        target_ext = _detect_file_extension(context.target_path or "", context.source_code or "")
        example_filename = f"test_boundary{target_ext}"
        example_magic = _EXAMPLE_MAGIC_BY_EXT.get(target_ext)
        example_hex = (example_magic.hex() + "...") if example_magic else "<raw byte stream as hex>"
        format_guidance = _FORMAT_GUIDANCE_BY_EXT.get(target_ext, _DEFAULT_FORMAT_GUIDANCE)

        prompt = f"""You are an expert Software Quality Assurance & Test Verification Engineer.
Objective:
Construct targeted boundary test case inputs (command arguments, raw byte buffers, or structured file streams) designed to thoroughly test edge-case memory handling, array bounds, format parsers, and arithmetic limits for automated regression verification.

Target Analysis & Edge Cases to Test:
{joined_vuln_desc}
{cve_spec_str}
{poc_context_str}

Source Code Context:
{scoped_source}

Test Case Construction Guidelines:
1. Delivery Mode Alignment:
   - For 'file' delivery mode: Supply the complete raw binary byte stream as a hex string in 'raw_bytes_hex' (e.g. "{example_hex}"). Provide target filename in 'args' (e.g. ["{example_filename}"]) -- vary the filename per payload, do not reuse this literal example.
   - For 'args' delivery mode: Supply target argument arrays in 'args' (do not prepend target executable name).
   - For 'stdin' / 'tcp' / 'http' delivery modes: Supply payload strings in 'input_data'.
2. Structural Integrity:
   - {format_guidance}
   - Ensure all JSON string fields are valid, single-line text without unescaped control characters.
{lang_rules}

Required Schema:
Return JSON adhering strictly to:
{{
  "payloads": [
    {{
      "args": ["{example_filename}"],
      "input_data": "",
      "raw_bytes_hex": "{example_hex}",
      "reason": "Technical rationale explaining test case structure and boundary parameters"
    }}
  ]
}}
"""

        try:
            data = None
            synthesis_error = None
            refusal_keywords = [
                "cannot fulfill", "safety", "policy", "cannot generate", "unable to provide",
                "as an ai", "i cannot", "sorry", "exploit payloads", "proof-of-concept"
            ]

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
                        current_prompt = prompt
                        # On second attempt (if first attempt timed out/errored), condense source context to speed up generation
                        if attempt == 1 and len(scoped_source.splitlines()) > 60:
                            condensed_lines = scoped_source.splitlines()[:60]
                            condensed_source = "\n".join(condensed_lines) + "\n// ... [Context trimmed for fast retry generation]"
                            current_prompt = prompt.replace(scoped_source, condensed_source)

                        try:
                            with AiActivityHeartbeat(task_name=f"synthesizing test payloads with {model_candidate}"):
                                response = self.engine.client.models.generate_content(
                                    model=model_candidate,
                                    contents=current_prompt,
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
                            if parsed and parsed.get("payloads"):
                                # Check for safety refusal text in reasons or args
                                valid_items = []
                                for item in parsed["payloads"]:
                                    item_text = (item.get("reason", "") + " " + " ".join(item.get("args", []))).lower()
                                    if not any(k in item_text for k in refusal_keywords):
                                        valid_items.append(item)
                                if valid_items and not (len(valid_items) == 1 and "Fallback" in valid_items[0].get("reason", "")):
                                    parsed["payloads"] = valid_items
                                    data = parsed
                                    break
                                else:
                                    console.print(f"[dim]  [PayloadSynthesizerAgent] Model '{model_candidate}' returned refusal or empty args. Trying candidate...[/dim]")
                        except Exception as e:
                            synthesis_error = e
                            err_upper = str(e).upper()
                            if "429" in err_upper or "RESOURCE_EXHAUSTED" in err_upper:
                                import time
                                console.print("[yellow]  Rate limit (429) on synthesis. Waiting 15s to cool down...[/yellow]")
                                time.sleep(15)
                                continue
                            elif any(k in err_upper for k in ["NOT_FOUND", "404", "INVALID_ARGUMENT"]):
                                console.print(f"[dim]  Model '{model_candidate}' not available (404/unsupported). Trying next candidate...[/dim]")
                                break
                            elif any(k in err_upper for k in ["504", "TIMEOUT", "503", "SERVER_ERROR", "DEADLINE_EXCEEDED", "READTIMEOUT"]):
                                if attempt < 1:
                                    wait_time = (attempt + 1) * 3
                                    console.print(f"[yellow]  Transient timeout on '{model_candidate}'. Retrying with condensed context in {wait_time}s (attempt 2/2)...[/yellow]")
                                    import time
                                    time.sleep(wait_time)
                                    continue
                                else:
                                    console.print(f"[yellow]  Model '{model_candidate}' timed out after retry. Switching to fallback candidate...[/yellow]")
                                    break
                            elif attempt < 1:
                                import time
                                time.sleep(2)
                                continue
                            else:
                                break
                    if data is not None and data.get("payloads"):
                        break

                if data is None:
                    context.synthesis_failed = True
                    context.synthesis_error = f"{type(synthesis_error).__name__}: {synthesis_error}" if synthesis_error else "Empty response"
                    context.logs.append(f"[PayloadSynthesizerAgent] WARNING: AI payload synthesis failed ({context.synthesis_error}). No payloads generated for this batch.")
                    data = {"payloads": []}
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

            # The synthesis prompt includes a literal filename in its JSON schema
            # example (e.g. "test_boundary.png"); the AI sometimes echoes that
            # example verbatim across multiple payloads instead of varying it. The
            # actual on-disk file executed is always uniquified separately
            # (executor.py uses a UUID temp filename), so this doesn't cause a real
            # execution collision -- but the *displayed* filename in reports/logs
            # would be indistinguishable across genuinely different payloads, which
            # reads as "these are duplicates" even when they aren't. Track and
            # de-duplicate the declared filename across this run's payloads so
            # reporting stays unambiguous.
            seen_file_arg_names: set[str] = set()
            if context.delivery_mode == "file":
                for existing in context.active_payloads:
                    if existing.args:
                        seen_file_arg_names.add(existing.args[-1])

            for p in payloads:
                args = p.get("args", [])
                input_data = p.get("input_data", "")
                raw_bytes_hex = p.get("raw_bytes_hex")
                reason = p.get("reason", "")
                item_is_fallback = bool(p.get("is_fallback", is_synthesis_fallback) or "Fallback" in reason)

                # SYSTEMIC VALIDATION: discard payload items the AI returned with no
                # actual content (reasoning text but no args/input_data/raw_bytes_hex)
                # -- this tool is AI-assisted, so an empty AI-produced item is
                # dropped rather than silently replaced with hardcoded filler.
                is_empty_payload = (not args or len(args) == 0) and (not input_data or not str(input_data).strip()) and not raw_bytes_hex
                if is_empty_payload:
                    context.logs.append(f"[PayloadSynthesizerAgent] WARNING: Discarding empty AI-produced payload (reasoning without args/input_data, Reason: {reason}).")
                    continue
                elif context.delivery_mode == "file" and (not args or len(args) == 0):
                    args = [f"payload_poc_{valid_payloads_added+1}{target_ext}"]
                    context.logs.append(f"[PayloadSynthesizerAgent] Info: Auto-populated missing args filename ({args[0]}) for file delivery mode.")

                if context.delivery_mode == "file" and args:
                    base_name = args[-1]
                    if base_name in seen_file_arg_names:
                        stem, dot, ext = base_name.rpartition(".")
                        suffix = 2
                        candidate = f"{stem}_{suffix}.{ext}" if dot else f"{base_name}_{suffix}"
                        while candidate in seen_file_arg_names:
                            suffix += 1
                            candidate = f"{stem}_{suffix}.{ext}" if dot else f"{base_name}_{suffix}"
                        context.logs.append(f"[PayloadSynthesizerAgent] Info: Renamed duplicate payload filename '{base_name}' -> '{candidate}' to keep payloads distinguishable in reports.")
                        args = args[:-1] + [candidate]
                    seen_file_arg_names.add(args[-1])

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

            # Final check: zero usable payloads means synthesis genuinely produced
            # nothing this batch -- honestly report that rather than injecting
            # hardcoded filler content. The orchestrator's own stagnation guard
            # already handles a synthesizer batch that produces zero payloads.
            if valid_payloads_added == 0:
                context.synthesis_failed = True
                context.logs.append("[PayloadSynthesizerAgent] WARNING: Zero usable payloads produced by AI synthesis for this batch.")

        except Exception as e:
            context.synthesis_failed = True
            context.synthesis_error = str(e)
            context.logs.append(f"[PayloadSynthesizerAgent] Error generating payloads: {e}")
            context.logs.append("[PayloadSynthesizerAgent] Added safe fallback payload")

        return context
