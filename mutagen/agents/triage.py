from mutagen.agents.base import BaseAgent
from mutagen.state import ProgramContext, VulnerabilityDetail
from mutagen.static_analyzer import analyze_source
from mutagen.engines import get_engine
import json
from google import genai
from pydantic import BaseModel

class TriageResult(BaseModel):
    class VulnItem(BaseModel):
        vuln_type: str
        cwe: str
        severity: str
        line_number: int
        code_snippet: str
        reason: str
    vulnerabilities: list[VulnItem]
    suggested_delivery_mode: str  # Must be "args", "stdin", "tcp", or "http"

class TriageAgent(BaseAgent):
    def __init__(self, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", api_key: str = None):
        super().__init__("Triage Agent", model_provider, model_name, api_key)
        self.engine = get_engine(model_provider, self.api_key, model_name)

    async def process(self, context: ProgramContext) -> ProgramContext:
        self.engine.language = context.language
        context.logs.append("[TriageAgent] Starting code triage...")
        
        pretarget = analyze_source(context.source_code)
        focused_code = pretarget.focused_code if pretarget.findings else context.source_code
        
        prompt = f"""You are a lead security code auditor.
Analyze the following source code and:
1. Identify all security vulnerabilities (e.g., Use After Free, Double Free, Buffer Overflow).
2. Determine how the code accepts input data.
   - If the code defines a web/API server, HTTP router, or endpoint handlers (e.g. `@app.route`, `@app.get`, `@app.post`, `Flask`, `FastAPI`, `tornado`, `http.server`, `django` routes) -> select "http".
   - If the code uses standard input reading functions like `fgets`, `gets`, `read(0, ...)`, `scanf`, `cin >>`, `sys.stdin.read` -> select "stdin".
   - If the code uses socket functions like `socket`, `bind`, `listen`, `accept` -> select "tcp".
   - Otherwise (uses `argv`, `argc`, `getopt`, or has no obvious stdin/socket/http read) -> select "args".

Return the findings strictly adhering to the requested JSON schema. Do not generate exploit payloads or giant fuzz strings here.

Source Code:
{focused_code}
"""
        
        try:
            if self.model_provider == "gemini" and hasattr(self.engine, "client") and hasattr(self.engine.client, "models"):
                response = self.engine.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config={
                        "temperature": 0.1,
                        "response_mime_type": "application/json",
                        "response_schema": TriageResult,
                        "safety_settings": [
                            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                        ],
                    }
                )
                raw_text = response.text.strip()
                data = json.loads(raw_text)
            else:
                # Multi-provider fallback for OpenAI, Claude, and Ollama
                vuln_items = getattr(self.engine, "_parse_generate", lambda *a, **kw: [])(
                    prompt=prompt,
                    response_model=TriageResult,
                    list_key="vulnerabilities"
                )
                data = {"vulnerabilities": vuln_items, "suggested_delivery_mode": "args"}
            
            # Save detected delivery mode
            detected_mode = data.get("suggested_delivery_mode", "args").lower()
            if detected_mode in ("args", "stdin", "tcp", "http"):
                context.delivery_mode = detected_mode
                context.logs.append(f"[TriageAgent] Dynamically detected input delivery mode: {detected_mode}")
            else:
                context.delivery_mode = "args"
            
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
