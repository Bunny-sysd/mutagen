from mutagen.agents.base import BaseAgent
from mutagen.state import ProgramContext
from mutagen.ast_validator import validate_c_source
from mutagen.compiler import compile_target
from mutagen.executor import execute_payload
import os
import tempfile

class StructuralValidatorAgent(BaseAgent):
    def __init__(self, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", compiler_path: str = "gcc", delivery_mode: str = "args", api_key: str = None):
        super().__init__("Structural Validator Agent", model_provider, model_name, api_key)
        self.compiler_path = compiler_path
        self.delivery_mode = delivery_mode

    async def process(self, context: ProgramContext) -> ProgramContext:
        context.logs.append("[StructuralValidatorAgent] Running structural validation checks...")
        
        patched_code = context.proposed_patches.get("primary_patch")
        if not patched_code:
            context.logs.append("[StructuralValidatorAgent] No proposed patch found to validate.")
            context.verification_status = "REGRESSION_FAILED"
            return context

        # 1. Run Tree-sitter AST Pre-Check (C/C++ only)
        if context.language == "c":
            result = validate_c_source(patched_code)
            if not result.is_valid:
                err_msg = ", ".join(f"line {e.line}: {e.message}" for e in result.errors)
                context.logs.append(f"[StructuralValidatorAgent] AST Validation failed: {err_msg}")
                context.verification_status = "REGRESSION_FAILED"
                return context
            context.logs.append(f"[StructuralValidatorAgent] AST Validation passed. Parsed {result.node_count} nodes.")
        else:
            context.logs.append(f"[StructuralValidatorAgent] Skipping Tree-sitter AST check for non-C language: {context.language}")

        # 2. Write patch to temporary file and compile/validate it
        ext = os.path.splitext(context.target_path)[1].lower()
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_c_path = os.path.join(tmpdir, f"patched_target{ext}")
            with open(temp_c_path, "w", encoding="utf-8") as f:
                f.write(patched_code)
                
            try:
                exe_path = compile_target(temp_c_path, self.compiler_path)
                context.logs.append(f"[StructuralValidatorAgent] Patched target compiled successfully: {exe_path}")
            except Exception as e:
                context.logs.append(f"[StructuralValidatorAgent] Compilation of patched target failed: {e}")
                context.verification_status = "REGRESSION_FAILED"
                return context

            # 3. Fire all reproduction crash payloads at the patched target
            active_crashes = [p for p in context.active_payloads if p.crash_type is not None]
            if not active_crashes:
                # No crashes were detected previously, so compile success is enough
                context.verification_status = "VERIFIED_SECURE"
                context.logs.append("[StructuralValidatorAgent] Verification passed (no active crashes were recorded).")
                return context

            all_secured = True
            for crash in active_crashes:
                # For stdin mode, ensure the payload string is passed as input_data if args is set but input_data is empty
                input_data = crash.input_data
                if self.delivery_mode == "stdin" and not input_data and crash.args:
                    input_data = "\n".join(crash.args)

                res = execute_payload(
                    exe_path=exe_path,
                    args=crash.args,
                    input_data=input_data,
                    delivery_mode=self.delivery_mode,
                    timeout=5
                )
                
                # Check if it still crashes using the executor's oracle-resolved crashed flag
                is_still_crashing = res.get("crashed", False)
                if is_still_crashing:
                    context.logs.append(f"[StructuralValidatorAgent] Verification failed: Payload {crash.args} still triggered vulnerability (type: {res.get('crash_type')}).")
                    all_secured = False
                    break
            
            if all_secured:
                context.verification_status = "VERIFIED_SECURE"
                context.logs.append("[StructuralValidatorAgent] Verification PASSED! The patch blocks all crash payloads.")
            else:
                context.verification_status = "REGRESSION_FAILED"

        return context
