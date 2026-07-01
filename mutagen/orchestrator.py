import sys
from mutagen.state import ProgramContext
from mutagen.agents.triage import TriageAgent
from mutagen.agents.synthesizer import PayloadSynthesizerAgent
from mutagen.agents.supervisor import FuzzingSupervisorAgent
from mutagen.agents.patcher import PatchEngineerAgent
from mutagen.agents.validator import StructuralValidatorAgent

class AgentOrchestrator:
    def __init__(self, target_path: str, source_code: str, provider: str = "gemini", model: str = "gemini-2.5-flash", compiler: str = "gcc", delivery_mode: str = "args", api_key: str = None):
        platform = sys.platform
        self.context = ProgramContext(
            target_path=target_path,
            language="c" if target_path.endswith(".c") else "python",
            os_platform=platform,
            source_code=source_code
        )
        
        # Initialize micro-agents
        self.triage_agent = TriageAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.synthesizer_agent = PayloadSynthesizerAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.supervisor_agent = FuzzingSupervisorAgent(model_provider=provider, model_name=model, compiler_path=compiler, delivery_mode=delivery_mode, api_key=api_key)
        self.patch_agent = PatchEngineerAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.validator_agent = StructuralValidatorAgent(model_provider=provider, model_name=model, compiler_path=compiler, delivery_mode=delivery_mode, api_key=api_key)

    async def run(self) -> ProgramContext:
        self.context.logs.append("[Orchestrator] Initializing Multi-Agent APR Swarm...")
        
        # 1. Run Triage Agent to find bugs
        self.context = await self.triage_agent.process(self.context)
        if not self.context.vulnerabilities:
            self.context.logs.append("[Orchestrator] Code appears clean. No vulnerabilities found.")
            return self.context

        # 2. Run Payload Synthesizer Agent to generate test inputs
        self.context = await self.synthesizer_agent.process(self.context)

        # 3. Run Fuzzing Supervisor to test compile & record crashes
        self.context = await self.supervisor_agent.process(self.context)
        active_crashes = [p for p in self.context.active_payloads if p.crash_type is not None]
        
        if not active_crashes:
            self.context.logs.append("[Orchestrator] No active crashes were reproduced by fuzzing.")
            return self.context

        # 4. Self-Healing Loop: Patch & Verify
        for attempt in range(1, 4):
            self.context.logs.append(f"[Orchestrator] Healing loop attempt {attempt}/3")
            
            # Run Patch Engineer
            self.context = await self.patch_agent.process(self.context)
            
            # Run Structural Validator
            self.context = await self.validator_agent.process(self.context)
            
            if self.context.verification_status == "VERIFIED_SECURE":
                self.context.logs.append("[Orchestrator] Secure patch generated and verified successfully!")
                break
                
        return self.context
