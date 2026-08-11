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
        focused_code = pretarget.focused_code if pretarget.findings else context.source_code

        # Enrich prompt with multi-file workspace call graph summary if available
        graph_summary = ""
        if context.target_path:
            from mutagen.project_graph import summarize_project_graph
            target_dir = os.path.dirname(os.path.abspath(context.target_path))
            graph_text = summarize_project_graph(target_dir)
            if "No multi-file workspace" not in graph_text:
                graph_summary = f"\n\nPROJECT WORKSPACE CONTEXT:\n{graph_text}\n"

        prompt = get_triage_prompt(context.language, focused_code)
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

        try:
            if self.model_provider == "gemini" and hasattr(self.engine, "client") and hasattr(self.engine.client, "models"):
                response = self.engine.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config={
                        "temperature": TRIAGE_TEMPERATURE,
                        "response_mime_type": "application/json",
                        "response_schema": TriageResult,
                        "safety_settings": GEMINI_SAFETY_OFF,
                    }
                )
                raw_text = response.text.strip()
                data = json.loads(raw_text)
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

            # Save detected delivery mode & apply global I/O primitive validation
            raw_detected_mode = data.get("suggested_delivery_mode", "args")
            context.delivery_mode = validate_and_sanitize_delivery_mode(
                context.source_code, raw_detected_mode, context.logs
            )

            context.logs.append(f"[TriageAgent] Dynamically detected input delivery mode: {context.delivery_mode}")

            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                detail = context.add_vulnerability(item)
                context.logs.append(f"[TriageAgent] Identified {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")
                context.notepad.append(f"Triage: Found {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")

        except Exception as e:
            from rich.console import Console
            console = Console(force_terminal=True, force_jupyter=False)
            console.print(f"[bold yellow]⚠️  Triage AI API unavailable ({type(e).__name__}: {e}). Falling back to static AST analyzer findings.[/bold yellow]")
            context.logs.append(f"[TriageAgent] Error during triage LLM call: {e}. Executing static analyzer fallback.")
            context.delivery_mode = "args"
            # Fallback to static analyzer findings if LLM fails
            if pretarget.findings:
                for finding in pretarget.findings:
                    detail = context.add_vulnerability(finding)
                    context.logs.append(f"[TriageAgent Fallback] Identified {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")
                    context.notepad.append(f"Triage fallback: Found {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")

        context.notepad.append(f"Triage: Dynamically selected input delivery mode: {context.delivery_mode}")
        return context
