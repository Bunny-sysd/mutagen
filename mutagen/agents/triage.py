import json
import os
from typing import Any

from pydantic import BaseModel

from mutagen.agents.base import BaseAgent
from mutagen.agents.prompts import get_triage_prompt
from mutagen.constants import DEFAULT_MODEL_GEMINI, DEFAULT_PROVIDER, TRIAGE_TEMPERATURE
from mutagen.engines import get_engine
from mutagen.safety import GEMINI_SAFETY_OFF
from mutagen.state import ProgramContext, VulnerabilityDetail
from mutagen.static_analyzer import analyze_source


def _normalize_finding(item: Any) -> VulnerabilityDetail:
    """
    Normalizes a finding from either LLM JSON dict response or StaticFinding dataclass
    into a standardized VulnerabilityDetail object using state boundary adapters.
    """
    return VulnerabilityDetail.from_any(item)


def validate_and_sanitize_delivery_mode(source_code: str, requested_mode: str, logs: list[str] = None) -> str:
    """
    Globally validates requested_mode against actual I/O primitives found in source_code.
    If requested_mode has zero supporting I/O primitives in the target codebase,
    sanitizes and falls back to a verified mode ('file', 'stdin', or 'args') and logs why.
    """
    mode = (requested_mode or "args").lower().strip()
    src_lower = (source_code or "").lower()

    tcp_primitives = [
        "socket(", "bind(", "listen(", "accept(", "connect(", "recv(", "recvfrom(",
        "tcplistener", "tcpstream", "net.listen", "net.dial", "socket.socket", "asyncio.open_connection"
    ]
    http_primitives = [
        "http", "flask", "fastapi", "express", "actix-web", "axum", "net/http",
        "httplib", "mg_start", "microhttpd", "web.app", "router.get", "app.get("
    ]
    file_primitives = [
        "fopen(", "fread(", "open(", "readfile(", "parse_file(", "file.read",
        "std::fs::", "os.open(", "fs.readfile", "ifstream", "file_get_contents",
        "png_create_read_struct", "png_init_io", "stbi_load", "image_begin_read"
    ]
    stdin_primitives = [
        "fgets(", "gets(", "read(0,", "scanf(", "cin >>", "sys.stdin",
        "std::io::stdin", "os.stdin", "readline("
    ]

    has_tcp = any(p in src_lower for p in tcp_primitives)
    has_http = any(p in src_lower for p in http_primitives)
    has_file = any(p in src_lower for p in file_primitives)
    has_stdin = any(p in src_lower for p in stdin_primitives)

    # 1. Reject TCP/HTTP if zero network primitives exist in target codebase
    if mode in ("tcp", "http") and not (has_tcp or has_http):
        fallback = "file" if has_file else ("stdin" if has_stdin else "args")
        msg = f"[TriageAgent SanityCheck] Requested delivery mode '{mode}' lacks network I/O primitives in target codebase. Correcting to '{fallback}' mode."
        if logs is not None:
            logs.append(msg)
        return fallback

    # 2. Upgrade args/none to file if target contains explicit file I/O primitives
    if mode in ("args", "none", "") and has_file:
        msg = "[TriageAgent SanityCheck] Target codebase contains verified file I/O primitives. Upgrading delivery mode to 'file'."
        if logs is not None:
            logs.append(msg)
        return "file"

    return mode if mode in ("args", "stdin", "file", "tcp", "http") else "args"


class TriageResult(BaseModel):
    class VulnItem(BaseModel):
        vuln_type: str
        cwe: str
        severity: str
        line_number: int
        code_snippet: str
        reason: str
    vulnerabilities: list[VulnItem]
    suggested_delivery_mode: str  # Must be "args", "stdin", "file", "tcp", or "http"

class TriageAgent(BaseAgent):
    def __init__(self, model_provider: str = DEFAULT_PROVIDER, model_name: str = DEFAULT_MODEL_GEMINI, api_key: str = None):
        super().__init__("Triage Agent", model_provider, model_name, api_key)
        self.engine = get_engine(model_provider, self.api_key, model_name)

    async def process(self, context: ProgramContext) -> ProgramContext:
        self.engine.language = context.language
        context.logs.append("[TriageAgent] Starting code triage...")

        pretarget = analyze_source(context.source_code)
        
        # Always provide the full, intact source code with 1-based line numbers for 100% precision
        code_lines = context.source_code.splitlines()
        numbered_source = "\n".join(f"{i+1:4d} | {line}" for i, line in enumerate(code_lines))

        # Enrich prompt with multi-file workspace call graph summary if available
        graph_summary = ""
        if context.target_path:
            from mutagen.project_graph import summarize_project_graph
            target_dir = os.path.dirname(os.path.abspath(context.target_path))
            graph_text = summarize_project_graph(target_dir)
            if "No multi-file workspace" not in graph_text:
                graph_summary = f"\n\nPROJECT WORKSPACE CONTEXT:\n{graph_text}\n"

        prompt = get_triage_prompt(context.language, numbered_source)

        # Include AST static findings as non-destructive hints
        if pretarget.findings:
            ast_hints = [f"- Line {f.line}: {f.call_name} ({f.pattern_type}, {f.cwe})" for f in pretarget.findings[:10]]
            prompt += "\n\n[STATIC AST DANGEROUS PATTERN HINTS]\n" + "\n".join(ast_hints) + "\n"

        if context.is_binary:
            binary_context = (
                f"\n\n[REVERSE ENGINEERING ANALYSIS CONTEXT]\n"
                f"- Decompiler Used: {context.decompiler_used or 'Ghidra'}\n"
                f"- Target Architecture: {context.architecture or 'Unknown'}\n"
                f"- Note: The source code above is pseudo-C generated via automated decompiler decompilation.\n"
                f"- Pay special attention to decompiled pointer arithmetic, type casts (undefined/uint), symbol cross-references, and function signature recovery errors.\n"
            )
            prompt += binary_context

        if graph_summary:
            prompt += graph_summary

        data = None
        triage_api_error = None

        from rich.console import Console
        console = Console(force_terminal=True, force_jupyter=False)

        # Build fallback model chain for Gemini triage
        models_to_try = [self.model_name] if self.model_name else []
        for m in ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]:
            if m not in models_to_try:
                models_to_try.append(m)

        for model_candidate in models_to_try:
            for attempt in range(2):
                try:
                    if self.model_provider == "gemini" and hasattr(self.engine, "client") and hasattr(self.engine.client, "models"):
                        from mutagen.engines.base import AiActivityHeartbeat
                        with AiActivityHeartbeat(task_name=f"triaging code architecture with {model_candidate}"):
                            response = self.engine.client.models.generate_content(
                                model=model_candidate,
                                contents=prompt,
                                config={
                                    "temperature": TRIAGE_TEMPERATURE,
                                    "response_mime_type": "application/json",
                                    "response_schema": TriageResult,
                                    "safety_settings": GEMINI_SAFETY_OFF,
                                }
                            )
                        raw_text = response.text.strip() if response and response.text else ""
                        if not raw_text:
                            raise ValueError("Empty response text from AI model")
                        try:
                            data = json.loads(raw_text)
                        except json.JSONDecodeError as jde:
                            from mutagen.engines.output_parser import repair_truncated_json
                            repaired = repair_truncated_json(raw_text)
                            if repaired and isinstance(repaired, dict):
                                data = repaired
                            elif repaired and isinstance(repaired, list):
                                data = {"vulnerabilities": repaired, "suggested_delivery_mode": "args"}
                            else:
                                raise jde
                    else:
                        # Multi-provider fallback for OpenAI, Claude, and Ollama
                        res_obj = getattr(self.engine, "_parse_generate", lambda *a, **kw: [])(
                            prompt=prompt,
                            response_model=TriageResult,
                            list_key="vulnerabilities"
                        )
                        if isinstance(res_obj, dict):
                            data = res_obj
                        elif isinstance(res_obj, list):
                            data = {"vulnerabilities": res_obj, "suggested_delivery_mode": "args"}
                        else:
                            data = {"vulnerabilities": [], "suggested_delivery_mode": "args"}

                    if data and isinstance(data, dict):
                        break
                except Exception as e:
                    triage_api_error = e
                    err_upper = str(e).upper()
                    if "429" in err_upper or "RESOURCE_EXHAUSTED" in err_upper:
                        import time
                        console.print("[yellow]  Rate limit (429) on triage. Waiting 15s to cool down...[/yellow]")
                        time.sleep(15)
                    elif any(k in err_upper for k in ["504", "TIMEOUT", "503", "SERVER_ERROR", "DEADLINE_EXCEEDED", "NOT_FOUND", "404"]):
                        console.print(f"[yellow]  Model '{model_candidate}' timed out (504/timeout). Switching to fallback model candidate...[/yellow]")
                        break
                    elif attempt < 1:
                        import time
                        time.sleep(2)
            if data is not None and isinstance(data, dict):
                break

        if data is None:
            context.triage_failed = True
            context.triage_error = f"{type(triage_api_error).__name__}: {triage_api_error}"
            context.logs.append(f"[TriageAgent] Error during triage LLM call: {context.triage_error}. Executing static analyzer fallback.")
            console.print(f"[bold yellow]⚠️  Triage AI API unavailable ({context.triage_error}). Falling back to static AST analyzer findings.[/bold yellow]")
            context.delivery_mode = "args"
            # Fallback to static analyzer findings if LLM fails
            if pretarget.findings:
                from mutagen.type_verifier import verify_finding_type_safety
                for finding in pretarget.findings:
                    detail = context.add_vulnerability(finding)
                    v_res = verify_finding_type_safety(
                        source_code=context.source_code,
                        line_number=detail.line_number,
                        cwe=detail.cwe,
                        vuln_type=detail.vuln_type,
                        language=context.language,
                        target_path=context.target_path
                    )
                    detail.metadata["verification_status"] = v_res.verification_status
                    detail.metadata["verification_annotation"] = v_res.annotation
                    detail.metadata["confidence"] = v_res.confidence
                    detail.metadata["is_false_positive_risk"] = v_res.is_false_positive_risk

                    if v_res.is_false_positive_risk:
                        context.logs.append(f"[TypeVerifier] {v_res.annotation} (Line {detail.line_number})")
                        console.print(f"[bold yellow]  [TypeVerifier] {v_res.annotation} (Line {detail.line_number})[/bold yellow]")
                    else:
                        context.logs.append(f"[TypeVerifier] Line {detail.line_number} verified: {v_res.annotation}")
                        console.print(f"[dim]  [TypeVerifier] Line {detail.line_number} verified: {v_res.annotation}[/dim]")

                    context.logs.append(f"[TriageAgent Fallback] Identified {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")
                    context.notepad.append(f"Triage fallback: Found {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")
        else:
            # Save detected delivery mode & apply global I/O primitive validation
            raw_detected_mode = data.get("suggested_delivery_mode", "args")
            context.delivery_mode = validate_and_sanitize_delivery_mode(
                context.source_code, raw_detected_mode, context.logs
            )

            context.logs.append(f"[TriageAgent] Dynamically detected input delivery mode: {context.delivery_mode}")

            from mutagen.type_verifier import verify_finding_type_safety

            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                # 1. Snippet Line Re-anchoring (Align line number from focused_code to full original source)
                code_snip = (item.get("code_snippet") or "").strip() if isinstance(item, dict) else getattr(item, "code_snippet", "")
                claimed_line = item.get("line_number", 1) if isinstance(item, dict) else getattr(item, "line", 1)

                if code_snip and context.source_code:
                    lines = context.source_code.splitlines()
                    claimed_idx = max(0, claimed_line - 1)
                    # If claimed line does not contain snippet, search full source for the exact line
                    if claimed_idx >= len(lines) or code_snip not in lines[claimed_idx]:
                        for idx, src_l in enumerate(lines):
                            if code_snip in src_l or (len(code_snip) > 10 and src_l.strip() and src_l.strip() in code_snip):
                                reanchored_line = idx + 1
                                if isinstance(item, dict):
                                    item["line_number"] = reanchored_line
                                else:
                                    setattr(item, "line", reanchored_line)
                                context.logs.append(f"[GroundingVerifier] Re-anchored finding line from {claimed_line} to {reanchored_line} based on exact source code snippet match.")
                                break

                detail = context.add_vulnerability(item)
                v_res = verify_finding_type_safety(
                    source_code=context.source_code,
                    line_number=detail.line_number,
                    cwe=detail.cwe,
                    vuln_type=detail.vuln_type,
                    language=context.language,
                    target_path=context.target_path
                )
                detail.metadata["verification_status"] = v_res.verification_status
                detail.metadata["verification_annotation"] = v_res.annotation
                detail.metadata["confidence"] = v_res.confidence
                detail.metadata["is_false_positive_risk"] = v_res.is_false_positive_risk

                if v_res.verification_status == "UNGROUNDED_FINDING":
                    context.logs.append(f"[GroundingVerifier] REJECTED / UNGROUNDED finding at line {detail.line_number}: {v_res.annotation}")
                    console.print(f"[bold red]  [GroundingVerifier] REJECTED / UNGROUNDED at Line {detail.line_number}: {v_res.annotation}[/bold red]")
                elif v_res.is_false_positive_risk:
                    context.logs.append(f"[TypeVerifier] {v_res.annotation} (Line {detail.line_number})")
                    console.print(f"[bold yellow]  [TypeVerifier] {v_res.annotation} (Line {detail.line_number})[/bold yellow]")
                else:
                    context.logs.append(f"[TypeVerifier] Line {detail.line_number} verified: {v_res.annotation}")
                    console.print(f"[dim]  [TypeVerifier] Line {detail.line_number} verified: {v_res.annotation}[/dim]")

                context.logs.append(f"[TriageAgent] Identified {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")
                context.notepad.append(f"Triage: Found {detail.vuln_type} at line {detail.line_number} ({detail.cwe}) [Status: {v_res.verification_status}]")

        context.notepad.append(f"Triage: Dynamically selected input delivery mode: {context.delivery_mode}")
        return context
