from mutagen.agents.base import BaseAgent
from mutagen.state import ProgramContext, CrashPayload
from mutagen.engines import get_engine
import json
from pydantic import BaseModel

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
        context.logs.append("[PayloadSynthesizerAgent] Synthesizing exploit payloads based on triage...")
        
        vuln_descriptions = []
        for v in context.vulnerabilities:
            vuln_descriptions.append(f"- {v.vuln_type} ({v.cwe}) at line {v.line_number}: {v.metadata.get('reason', '')}")
            
        prompt = f"""You are an expert security fuzzer.
Generate up to 5 diverse inputs / arguments that will trigger the identified vulnerabilities in the C source code below.

Vulnerabilities found:
{"\n".join(vuln_descriptions)}

Source Code:
{context.source_code}

RULES:
1. Provide argument arrays and input data to trigger the crash.
2. IMPORTANT: Keep all input data and argument strings under 1000 characters. Use short inputs that demonstrate the logic flow (e.g. trigger words like "ABORT" or short buffer strings of length 100) rather than huge strings that break parsing.
3. DO NOT prepend the program/target executable name (like ./a.out or ./fuzzer_target or argv[0]) to the 'args' list. The first item in the 'args' array must be the first actual argument string that the target program receives (i.e. argv[1]).
4. Return the results matching the requested JSON schema.
"""
        
        try:
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
            data = json.loads(raw_text)
            
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
