import json

from pydantic import BaseModel

from mutagen.agents.base import BaseAgent
from mutagen.agents.prompts import get_triage_prompt
from mutagen.engines import get_engine
from mutagen.safety import GEMINI_SAFETY_OFF
from mutagen.state import ProgramContext, VulnerabilityDetail
from mutagen.static_analyzer import analyze_source


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
    def __init__(self, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", api_key: str = None):
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
            import os
            from mutagen.project_graph import summarize_project_graph
            target_dir = os.path.dirname(os.path.abspath(context.target_path))
            graph_text = summarize_project_graph(target_dir)
            if "No multi-file workspace" not in graph_text:
                graph_summary = f"\n\nPROJECT WORKSPACE CONTEXT:\n{graph_text}\n"

        prompt = get_triage_prompt(context.language, focused_code)
        if graph_summary:
            prompt += graph_summary

        try:
            if self.model_provider == "gemini" and hasattr(self.engine, "client") and hasattr(self.engine.client, "models"):
                response = self.engine.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config={
                        "temperature": 0.1,
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

            # Save detected delivery mode
            detected_mode = data.get("suggested_delivery_mode", "args").lower()
            if detected_mode in ("args", "stdin", "file", "tcp", "http"):
                context.delivery_mode = detected_mode
            else:
                context.delivery_mode = "args"

            # Heuristic check: if code opens/reads files, auto-upgrade to 'file' mode
            source_lower = context.source_code.lower()
            file_indicators = ["fopen(", "fread(", "fscanf(", "readfile(", "parse_file(", "open("]
            if context.delivery_mode == "args" and any(ind in source_lower for ind in file_indicators):
                context.delivery_mode = "file"

            context.logs.append(f"[TriageAgent] Dynamically detected input delivery mode: {context.delivery_mode}")

            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                detail = VulnerabilityDetail(
                    vuln_type=item.get("vuln_type", "Memory Corruption"),
                    cwe=item.get("cwe", "CWE-120"),
                    severity=item.get("severity", "critical"),
                    line_number=item.get("line_number", 1),
                    code_snippet=item.get("code_snippet", ""),
                    metadata={"reason": item.get("reason", "")}
                )
                context.vulnerabilities.append(detail)
                context.logs.append(f"[TriageAgent] Identified {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")
                context.notepad.append(f"Triage: Found {detail.vuln_type} at line {detail.line_number} ({detail.cwe})")

        except Exception as e:
            context.logs.append(f"[TriageAgent] Error during triage LLM call: {e}")
            context.delivery_mode = "args"
            # Fallback to a basic AST check if LLM fails
            if pretarget.findings:
                for finding in pretarget.findings:
                    detail = VulnerabilityDetail(
                        vuln_type="Potential Danger",
                        cwe=finding.get("cwe", "CWE-120"),
                        severity="medium",
                        line_number=finding.get("line", 1),
                        code_snippet=finding.get("snippet", ""),
                        metadata={"reason": f"Dangerous call '{finding.get('name')}' identified by static analyzer"}
                    )
                    context.vulnerabilities.append(detail)
                    context.notepad.append(f"Triage fallback: Found potential danger at line {detail.line_number}")

        context.notepad.append(f"Triage: Dynamically selected input delivery mode: {context.delivery_mode}")
        return context
