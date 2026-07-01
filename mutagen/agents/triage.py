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

class TriageAgent(BaseAgent):
    def __init__(self, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", api_key: str = None):
        super().__init__("Triage Agent", model_provider, model_name, api_key)
        self.engine = get_engine(model_provider, self.api_key, model_name)

    async def process(self, context: ProgramContext) -> ProgramContext:
        context.logs.append("[TriageAgent] Starting code triage...")
        
        pretarget = analyze_source(context.source_code)
        focused_code = pretarget.focused_code if pretarget.findings else context.source_code
        
        prompt = f"""You are a lead security code auditor.
Analyze the following source code and identify all security vulnerabilities (e.g., Use After Free, Double Free, Buffer Overflow).
Return the findings strictly adhering to the requested JSON schema. Do not generate exploit payloads or giant fuzz strings here. Only identify the flaws.

Source Code:
{focused_code}
"""
        
        try:
            # Query genai Client directly with structured Pydantic schema for absolute reliability
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
                
        except Exception as e:
            context.logs.append(f"[TriageAgent] Error during triage LLM call: {e}")
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
                    
        return context
