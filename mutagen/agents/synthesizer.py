from mutagen.agents.base import BaseAgent
from mutagen.state import ProgramContext, CrashPayload
from mutagen.engines import get_engine
import json
from pydantic import BaseModel

from mutagen.agents.prompts import get_synthesizer_rules

class PayloadList(BaseModel):
    class PayloadItem(BaseModel):
        args: list[str]
        input_data: str
        reason: str
    payloads: list[PayloadItem]

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

        vuln_descriptions = [
            f"- {v.vuln_type} at line {v.line_number} ({v.cwe}): {v.metadata.get('reason', '')}"
            for v in context.vulnerabilities
        ]
        
        lang_rules = get_synthesizer_rules(context.language)

        prompt = f"""You are an elite offensive security researcher and exploit developer.
Target System Platform: {context.os_platform} (Language: {context.language})
Your objective is to generate exact crash/exploit payloads to reproduce the identified security flaws.

Vulnerabilities found:
{"\n".join(vuln_descriptions)}

Source Code:
{context.source_code}

RULES:
1. Provide argument arrays and input data to trigger the crash.
2. IMPORTANT: Keep all input data and argument strings under 1000 characters. Use short inputs that demonstrate the logic flow.
3. DO NOT prepend the program/target executable name to the 'args' list.
4. For logical vulnerabilities (like command injection), synthesize payloads that execute commands echoing known success strings (e.g., "echo vuln_triggered", "echo exploit_success", or "echo PWNED") or calling system status commands (e.g., "whoami", "id", or "systeminfo").
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
                        "safety_settings": [
                            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                        ],
                    }
                )
                raw_text = response.text.strip()
                if raw_text.startswith("```"):
                    parts = raw_text.split("```")
                    raw_text = parts[1] if len(parts) > 1 else raw_text
                    if raw_text.startswith("json"):
                        raw_text = raw_text[4:]
                    raw_text = raw_text.strip()
                
                try:
                    data = json.loads(raw_text)
                except Exception:
                    try:
                        data = json.loads(raw_text, strict=False)
                    except Exception:
                        # Fallback parsing regex for JSON structure if string escaping broke
                        import re
                        match = re.search(r'\{.*\}', raw_text, re.DOTALL)
                        if match:
                            data = json.loads(match.group(0), strict=False)
                        else:
                            raise
            else:
                # Multi-provider fallback for OpenAI, Claude, and Ollama
                payload_items = getattr(self.engine, "_parse_generate", lambda *a, **kw: [])(
                    prompt=prompt,
                    response_model=PayloadList,
                    list_key="payloads"
                )
                data = {"payloads": payload_items}
            
            payloads = data.get("payloads", [])
            for p in payloads:
                args = p.get("args", [])
                input_data = p.get("input_data", "")
                reason = p.get("reason", "")
                
                crash_payload = CrashPayload(
                    args=args,
                    input_data=input_data
                )
                context.active_payloads.append(crash_payload)
                context.logs.append(f"[PayloadSynthesizerAgent] Generated payload args: {args} (Reason: {reason})")
                
        except Exception as e:
            context.logs.append(f"[PayloadSynthesizerAgent] Error generating payloads: {e}")
            # Fallback
            context.active_payloads.append(CrashPayload(args=["ABORT"], input_data=""))
            context.logs.append("[PayloadSynthesizerAgent] Added fallback payload 'ABORT'")
            
        return context
