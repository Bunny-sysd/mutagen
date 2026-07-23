import sys
from mutagen.state import ProgramContext
from mutagen.agents.triage import TriageAgent
from mutagen.agents.synthesizer import PayloadSynthesizerAgent
from mutagen.agents.supervisor import FuzzingSupervisorAgent
from mutagen.agents.patcher import PatchEngineerAgent
from mutagen.agents.validator import StructuralValidatorAgent

from rich.console import Console
from rich.panel import Panel

console = Console(force_terminal=True)

class AgentOrchestrator:
    def __init__(self, target_path: str, source_code: str, provider: str = "gemini", model: str = "gemini-2.5-flash", compiler: str = "gcc", delivery_mode: str = "args", api_key: str = None):
        platform = sys.platform
        self.default_delivery_mode = delivery_mode
        self.context = ProgramContext(
            target_path=target_path,
            language="c" if target_path.endswith(".c") else "python",
            os_platform=platform,
            source_code=source_code,
            delivery_mode=delivery_mode
        )
        
        # Initialize micro-agents
        self.triage_agent = TriageAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.synthesizer_agent = PayloadSynthesizerAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.supervisor_agent = FuzzingSupervisorAgent(model_provider=provider, model_name=model, compiler_path=compiler, delivery_mode=delivery_mode, api_key=api_key)
        self.patch_agent = PatchEngineerAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.validator_agent = StructuralValidatorAgent(model_provider=provider, model_name=model, compiler_path=compiler, delivery_mode=delivery_mode, api_key=api_key)

    async def run(self) -> ProgramContext:
        console.print(Panel(
            "[bold cyan]PHASE 1: TRIAGE & AST AUDIT[/bold cyan]\n"
            "[dim]TriageAgent is analyzing code architecture & detecting input delivery mode...[/dim]",
            border_style="cyan"
        ))
        self.context.logs.append("[Orchestrator] Initializing Multi-Agent APR Swarm...")
        
        # 1. Run Triage Agent to find bugs & detect delivery mode
        self.context = await self.triage_agent.process(self.context)
        if not self.context.vulnerabilities:
            console.print("[bold green]✓ Triage Complete: Code appears clean. No vulnerabilities found.[/bold green]")
            self.context.logs.append("[Orchestrator] Code appears clean. No vulnerabilities found.")
            return self.context

        # Determine active delivery mode (user explicit override beats auto-detected)
        active_mode = self.default_delivery_mode
        if active_mode == "args" and self.context.delivery_mode != "args":
            active_mode = self.context.delivery_mode
            self.context.logs.append(f"[Orchestrator] Using dynamically detected delivery mode: {active_mode}")
            
        self.supervisor_agent.delivery_mode = active_mode
        self.validator_agent.delivery_mode = active_mode

        console.print(Panel(
            f"[bold yellow]PHASE 2: PAYLOAD SYNTHESIS[/bold yellow]\n"
            f"[dim]PayloadSynthesizerAgent is constructing targeted exploit payloads for {len(self.context.vulnerabilities)} vulnerability findings...[/dim]",
            border_style="yellow"
        ))

        # 2. Run Payload Synthesizer Agent to generate test inputs
        self.context = await self.synthesizer_agent.process(self.context)

        console.print(Panel(
            f"[bold magenta]PHASE 3: SUPERVISOR FUZZING & CRASH REPRODUCTION[/bold magenta]\n"
            f"[dim]FuzzingSupervisorAgent is executing {len(self.context.active_payloads)} test payloads (Delivery Mode: {active_mode})...[/dim]",
            border_style="magenta"
        ))

        # 3. Run Fuzzing Supervisor to test compile & record crashes
        self.context = await self.supervisor_agent.process(self.context)
        active_crashes = [p for p in self.context.active_payloads if p.crash_type is not None]
        
        if not active_crashes:
            console.print("[bold yellow]! No active crashes were reproduced by fuzzing.[/bold yellow]")
            self.context.logs.append("[Orchestrator] No active crashes were reproduced by fuzzing.")
            return self.context

        console.print(f"[bold red]💥 {len(active_crashes)} Crash(es) Reproduced! Launching Self-Healing Loop...[/bold red]")

        # 4. Self-Healing Loop: Patch & Verify
        for attempt in range(1, 4):
            console.print(Panel(
                f"[bold green]PHASE 4: SELF-HEALING LOOP (Attempt {attempt}/3)[/bold green]\n"
                "[dim]PatchEngineerAgent generating patch & StructuralValidatorAgent re-testing...[/dim]",
                border_style="green"
            ))
            self.context.logs.append(f"[Orchestrator] Healing loop attempt {attempt}/3")
            
            # Run Patch Engineer
            self.context = await self.patch_agent.process(self.context)
            
            # Run Structural Validator
            self.context = await self.validator_agent.process(self.context)
            
            if self.context.verification_status == "VERIFIED_SECURE":
                console.print("[bold green]✨ SECURE PATCH VERIFIED SUCCESSFULLY! Zero regressions detected.[/bold green]")
                self.context.logs.append("[Orchestrator] Secure patch generated and verified successfully!")
                break
                
        return self.context
