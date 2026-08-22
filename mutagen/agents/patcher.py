from mutagen.agents.base import BaseAgent
from mutagen.constants import DEFAULT_MODEL_GEMINI, DEFAULT_PROVIDER
from mutagen.engines import get_engine
from mutagen.state import ProgramContext


class PatchEngineerAgent(BaseAgent):
    def __init__(self, model_provider: str = DEFAULT_PROVIDER, model_name: str = DEFAULT_MODEL_GEMINI, api_key: str = None):
        super().__init__("Patch Engineer Agent", model_provider, model_name, api_key)
        self.engine = get_engine(model_provider, self.api_key, model_name)

    async def process(self, context: ProgramContext) -> ProgramContext:
        self.engine.language = context.language
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

        # Format target reasoning using notepad history if available
        reasoning = f"Triggered by crash payload args: {crash.args}"
        if context.notepad:
            reasoning += "\nPrevious Swarm Notepad Notes:\n" + "\n".join(f"- {note}" for note in context.notepad)

        # Resolve CWE: use the first specific (non-default) CWE from triage findings, fall back to CWE-120
        matched_cwe = "CWE-120"
        for v in context.vulnerabilities:
            if v.cwe and v.cwe != "CWE-120":
                matched_cwe = v.cwe
                break


        crash_data = {
            "vuln_type": crash.crash_type,
            "args": crash.args,
            "input_data": crash.input_data,
            "raw_bytes_hex": crash.raw_bytes_hex,
            "cwe": matched_cwe,
            "severity": "critical",
            "reason": reasoning
        }

        # Check if we have a previous bad patch to refine
        bad_patch = context.get_primary_patch()

        import re

        from rich.console import Console

        from mutagen.editor import VirtualCodeEditor
        from mutagen.engines.output_parser import strip_code_fences
        console = Console(force_terminal=True, force_jupyter=False)

        # 1. Initialize Virtual Code Editor workspace with precise target scope
        target_line = 1
        target_func = None

        if context.vulnerabilities:
            for v in context.vulnerabilities:
                if getattr(v, "line_number", 0) > 1:
                    target_line = v.line_number
                    break
                if getattr(v, "function_name", None) and v.function_name != "<unknown>":
                    target_func = v.function_name
                    break

        # Check logs and notepad for crashing function name or line numbers
        if (target_line == 1 and not target_func):
            combined_history = " ".join(context.notepad + context.logs)
            m_line = re.search(r'[\w\-]+\.[c|cpp|h]:(\d+)', combined_history)
            if m_line:
                target_line = int(m_line.group(1))
            m_fn = re.search(r'(?:in|function|called|at)\s+[`\'"]?([a-zA-Z_][a-zA-Z0-9_]{3,})[`\'"]?', combined_history)
            if m_fn and m_fn.group(1).lower() not in ("main", "error", "warning", "failed", "passed", "return"):
                target_func = m_fn.group(1)

        editor = VirtualCodeEditor(
            source_code=context.source_code,
            language=context.language,
            filename=context.target_path
        )
        if target_func:
            editor.open_function_scope(target_func)
        else:
            editor.open_vulnerable_scope(target_line)

        editor.print_editor_status()

        candidate = None
        if bad_patch and context.verification_status != "VERIFIED_SECURE":
            context.logs.append("[PatchEngineerAgent] Refining previous failed patch in VirtualCodeEditor...")
            console.print(f"[dim]  🤖 [PatchEngineerAgent] Refining patch using AI engine '{self.model_provider}' (Model: {self.model_name or DEFAULT_MODEL_GEMINI})...[/dim]")
            clean_bad_patch = strip_code_fences(bad_patch)

            # Extract the bad scope from previous attempt
            bad_editor = VirtualCodeEditor(clean_bad_patch, language=context.language, filename=context.target_path)
            bad_editor.open_vulnerable_scope(target_line)
            bad_snippet = bad_editor.active_scope.body if bad_editor.active_scope else clean_bad_patch

            # Retrieve last log or compilation error
            error_message = context.logs[-1] if context.logs else "Unknown verification error"
            if context.notepad:
                error_message += "\n\nShared Swarm Notepad history:\n" + "\n".join(f"- {note}" for note in context.notepad)

            candidate = self.engine.refine_patch(
                source_code=editor.active_scope.original_body if editor.active_scope else context.source_code,
                bad_patch=bad_snippet,
                error_message=error_message,
                crash_data=crash_data,
                debug=True
            )
        else:
            context.logs.append("[PatchEngineerAgent] Generating fresh patch in VirtualCodeEditor...")
            console.print(f"[dim]  🤖 [PatchEngineerAgent] Generating fresh patch using AI engine '{self.model_provider}' (Model: {self.model_name or DEFAULT_MODEL_GEMINI})...[/dim]")
            candidate = self.engine.generate_patch(
                source_code=editor.active_scope.body if editor.active_scope else context.source_code,
                crash_data=crash_data,
                debug=True
            )

        if candidate and editor.apply_patch_candidate(candidate):
            # Run immediate pre-flight AST syntax check inside the editor
            is_valid, ast_msg = editor.run_pre_flight_check()
            if not is_valid:
                console.print(f"[bold yellow]  ⚠️ [VirtualCodeEditor] Pre-flight AST syntax warning: {ast_msg}[/bold yellow]")
                context.notepad.append(f"VirtualCodeEditor PreFlight: {ast_msg}")
            else:
                console.print("[dim]  ✓ [VirtualCodeEditor] Pre-flight AST syntax check passed.[/dim]")

            # Print rich colorized diff preview
            editor.print_diff_preview()

            full_patched_code = editor.get_full_patched_code()
            context.set_primary_patch(full_patched_code)
            context.logs.append("[PatchEngineerAgent] Proposed patch committed to context via VirtualCodeEditor.")
            context.notepad.append(f"PatchEngineerAgent: Proposed secure patch implementation (Revision {len(context.notepad) + 1})")
        else:
            context.logs.append("[PatchEngineerAgent] Failed to generate patch candidate.")
            console.print("[bold yellow]  ⚠️ AI engine was unable to produce a patch candidate.[/bold yellow]")

        return context
