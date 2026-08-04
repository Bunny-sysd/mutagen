import sys

from rich.console import Console
from rich.panel import Panel

from mutagen.agents.patcher import PatchEngineerAgent
from mutagen.agents.supervisor import FuzzingSupervisorAgent
from mutagen.agents.synthesizer import PayloadSynthesizerAgent
from mutagen.agents.triage import TriageAgent
from mutagen.agents.validator import StructuralValidatorAgent
from mutagen.constants import (
    DEFAULT_EXEC_TIMEOUT,
    DEFAULT_MAX_PATCH_RETRIES,
    DEFAULT_MODEL_GEMINI,
    DEFAULT_PROVIDER,
)
from mutagen.state import ProgramContext

console = Console(force_terminal=True)

class AgentOrchestrator:
    def __init__(
        self,
        target_path: str,
        source_code: str,
        provider: str = DEFAULT_PROVIDER,
        model: str = DEFAULT_MODEL_GEMINI,
        compiler: str = "gcc",
        delivery_mode: str = "args",
        api_key: str = None,
        max_patch_retries: int = DEFAULT_MAX_PATCH_RETRIES,
        execution_timeout: int = DEFAULT_EXEC_TIMEOUT,
    ):
        platform = sys.platform
        self.default_delivery_mode = delivery_mode
        self.max_patch_retries = max_patch_retries
        ext = target_path.lower().split(".")[-1] if "." in target_path else ""
        lang_map = {
            "c": "c",
            "cpp": "c++",
            "cxx": "c++",
            "cc": "c++",
            "rs": "rust",
            "go": "go",
            "java": "java",
            "cs": "csharp",
            "py": "python"
        }
        detected_lang = lang_map.get(ext, "c" if target_path.endswith(".c") else "python")
        self.context = ProgramContext(
            target_path=target_path,
            language=detected_lang,
            os_platform=platform,
            source_code=source_code,
            delivery_mode=delivery_mode
        )

        # Initialize micro-agents — threading execution_timeout through supervisor and validator
        self.triage_agent = TriageAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.synthesizer_agent = PayloadSynthesizerAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.supervisor_agent = FuzzingSupervisorAgent(
            model_provider=provider,
            model_name=model,
            compiler_path=compiler,
            delivery_mode=delivery_mode,
            api_key=api_key,
            execution_timeout=execution_timeout,
        )
        self.patch_agent = PatchEngineerAgent(model_provider=provider, model_name=model, api_key=api_key)
        self.validator_agent = StructuralValidatorAgent(
            model_provider=provider,
            model_name=model,
            compiler_path=compiler,
            delivery_mode=delivery_mode,
            api_key=api_key,
            execution_timeout=execution_timeout,
        )

    def gate_docker_sandbox_safety(self, ci_mode: bool = False, force_no_sandbox: bool = False) -> None:
        """
        CROSS-CUTTING SAFETY GATE:
        Detects Docker daemon availability upfront using 'docker info'.
        If Docker is available and sandboxing is requested/defaulted, enables container execution.
        If Docker is UN-available:
          - Non-interactive / CI mode: ABORTS immediately before compiling/executing binaries.
          - Interactive TTY mode: Prompts user explicitly to confirm unsandboxed host execution.
        """
        import os
        from mutagen.executor import _check_docker_functional
        docker_available = _check_docker_functional()
        self.context.docker_available = docker_available
        self.context.ci_mode = ci_mode or bool(os.environ.get("CI")) or not sys.stdin.isatty()

        if force_no_sandbox:
            self.context.sandboxed = False
            self.context.user_confirmed_unsandboxed = True
            self.context.logs.append("[SafetyGate] Explicit --no-sandbox flag provided. Proceeding unsandboxed.")
            return

        if docker_available:
            self.context.sandboxed = True
            self.context.user_confirmed_unsandboxed = False
            self.context.logs.append("[SafetyGate] Docker daemon responsive. Executing in isolated container sandbox.")
            from mutagen.executor import ensure_docker_image_ready
            ensure_docker_image_ready()
            return

        # Docker is NOT available:
        if self.context.ci_mode:
            console.print("[bold red]❌ SAFETY ERROR: Docker daemon is unavailable, and Mutagen is running in non-interactive/CI mode.[/bold red]")
            console.print("[bold red]Unsandboxed execution in non-interactive CI environments is disabled for host safety. Aborting.[/bold red]")
            self.context.logs.append("[SafetyGate] ABORTED: Docker unavailable in non-interactive/CI mode.")
            sys.exit(1)

        # Interactive TTY Mode Prompt:
        console.print("\n[bold yellow]⚠️  DOCKER NOT AVAILABLE[/bold yellow]")
        console.print("[yellow]Mutagen could not connect to a responsive Docker daemon.[/yellow]")
        console.print("[yellow]Fuzzing payloads are specifically designed to trigger crashes and memory corruption.[/yellow]")
        console.print("[yellow]Running them without container isolation means they will execute directly against this machine's real filesystem and process space.\n[/yellow]")
        console.print("Do you want to:")
        console.print("  [1] Proceed anyway, UNSANDBOXED, on this host (not recommended)")
        console.print("  [2] Abort and fix Docker first\n")

        try:
            choice = input("[?] Selection [1/2]: ").strip().lower()
            if choice in ("1", "y", "yes"):
                self.context.sandboxed = False
                self.context.user_confirmed_unsandboxed = True
                self.context.logs.append("[SafetyGate] User explicitly confirmed unsandboxed host execution.")
                console.print("[yellow][!] Proceeding with UNSANDBOXED host execution (user confirmed).[/yellow]\n")
            else:
                console.print("[bold red]Aborting run. Please start your Docker daemon and try again.[/bold red]")
                self.context.logs.append("[SafetyGate] ABORTED: User declined unsandboxed host execution.")
                sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold red]Aborted by user.[/bold red]")
            sys.exit(1)

    async def run(self) -> ProgramContext:
        console.print(Panel(
            "[bold cyan]PHASE 1/4 [25%]: TRIAGE & AST AUDIT[/bold cyan]\n"
            "[dim]TriageAgent is analyzing code architecture & detecting input delivery mode...[/dim]",
            border_style="cyan"
        ))
        self.context.logs.append("[Orchestrator] Initializing Multi-Agent APR Swarm...")

        # 1. Run Triage Agent to find bugs & detect delivery mode
        self.context = await self.triage_agent.process(self.context)
        if not self.context.vulnerabilities:
            console.print("[bold green][100%] [✓] Analysis Complete: Code appears clean. No vulnerabilities found.[/bold green]")
            self.context.logs.append("[Orchestrator] Code appears clean. No vulnerabilities found.")
            return self.context

        # Determine active delivery mode (user explicit override beats auto-detected)
        active_mode = self.default_delivery_mode
        if active_mode == "args" and self.context.delivery_mode != "args":
            active_mode = self.context.delivery_mode
            self.context.logs.append(f"[Orchestrator] Using dynamically detected delivery mode: {active_mode}")

        self.supervisor_agent.delivery_mode = active_mode
        self.validator_agent.delivery_mode = active_mode
        self.supervisor_agent.sandbox = "docker" if self.context.sandboxed else "none"
        self.validator_agent.sandbox = "docker" if self.context.sandboxed else "none"

        console.print(Panel(
            f"[bold yellow]PHASE 2/4 [50%]: PAYLOAD SYNTHESIS[/bold yellow]\n"
            f"[dim]PayloadSynthesizerAgent is constructing targeted exploit payloads for {len(self.context.vulnerabilities)} vulnerability findings...[/dim]",
            border_style="yellow"
        ))

        # 2. Run Payload Synthesizer Agent to generate test inputs
        self.context = await self.synthesizer_agent.process(self.context)

        console.print(Panel(
            f"[bold magenta]PHASE 3/4 [75%]: SUPERVISOR FUZZING & CRASH REPRODUCTION[/bold magenta]\n"
            f"[dim]FuzzingSupervisorAgent is executing {len(self.context.active_payloads)} test payloads (Delivery Mode: {active_mode})...[/dim]",
            border_style="magenta"
        ))

        # 3. Run Fuzzing Supervisor to test compile & record crashes
        self.context = await self.supervisor_agent.process(self.context)
        active_crashes = [p for p in self.context.active_payloads if p.crash_type is not None]

        if not active_crashes:
            console.print(f"[bold yellow][100%] [!] Execution Complete: Tested {len(self.context.active_payloads)} payload(s). No active crashes reproduced (target may contain mitigations or require specific inputs).[/bold yellow]")
            self.context.logs.append("[Orchestrator] No active crashes were reproduced by fuzzing.")
            return self.context

        console.print(f"[bold red]💥 {len(active_crashes)} Crash(es) Reproduced! Launching Self-Healing Loop...[/bold red]")

        # 4. Self-Healing Loop: Patch & Verify — uses the configured max_patch_retries
        for attempt in range(1, self.max_patch_retries + 1):
            console.print(Panel(
                f"[bold green]PHASE 4/4 [100%]: SELF-HEALING LOOP (Attempt {attempt}/{self.max_patch_retries})[/bold green]\n"
                "[dim]PatchEngineerAgent generating patch & StructuralValidatorAgent re-testing...[/dim]",
                border_style="green"
            ))
            self.context.logs.append(f"[Orchestrator] Healing loop attempt {attempt}/{self.max_patch_retries}")

            # Run Patch Engineer
            self.context = await self.patch_agent.process(self.context)

            # Run Structural Validator
            self.context = await self.validator_agent.process(self.context)

            if self.context.verification_status == "VERIFIED_SECURE":
                console.print("[bold green][100%] ✨ SECURE PATCH VERIFIED SUCCESSFULLY! Zero regressions detected.[/bold green]")
                self.context.logs.append("[Orchestrator] Secure patch generated and verified successfully!")
                break

        return self.context
