from mutagen.agents.base import BaseAgent
from mutagen.state import ProgramContext
from mutagen.engines import get_engine

class PatchEngineerAgent(BaseAgent):
    def __init__(self, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", api_key: str = None):
        super().__init__("Patch Engineer Agent", model_provider, model_name, api_key)
        self.engine = get_engine(model_provider, self.api_key, model_name)

    async def process(self, context: ProgramContext) -> ProgramContext:
        context.logs.append("[PatchEngineerAgent] Generating secure patch code...")
        
        # Get the first crash payload that triggered
        crash = None
        for p in context.active_payloads:
            if p.crash_type is not None:
                crash = p
                break
                
        if not crash:
            context.logs.append("[PatchEngineerAgent] No crashes detected to patch.")
            return context

        crash_data = {
            "vuln_type": crash.crash_type,
            "args": crash.args,
            "input_data": crash.input_data,
            "cwe": "CWE-120",
            "severity": "critical"
        }

        # Check if we have a previous bad patch to refine
        bad_patch = context.proposed_patches.get("primary_patch")
        
        if bad_patch and context.verification_status != "VERIFIED_SECURE":
            context.logs.append("[PatchEngineerAgent] Refining previous failed patch...")
            # Retrieve last log or compilation error
            error_message = context.logs[-1] if context.logs else "Unknown verification error"
            patched_code = self.engine.refine_patch(
                source_code=context.source_code,
                bad_patch=bad_patch,
                error_message=error_message,
                crash_data=crash_data,
                debug=True
            )
        else:
            context.logs.append("[PatchEngineerAgent] Generating fresh initial patch...")
            patched_code = self.engine.generate_patch(
                source_code=context.source_code,
                crash_data=crash_data,
                debug=True
            )
            
        if patched_code:
            context.proposed_patches["primary_patch"] = patched_code
            context.logs.append("[PatchEngineerAgent] Proposed patch saved.")
        else:
            context.logs.append("[PatchEngineerAgent] Failed to generate patch.")
            
        return context
