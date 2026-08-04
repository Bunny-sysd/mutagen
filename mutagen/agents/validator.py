import os
import tempfile

from mutagen.agents.base import BaseAgent
from mutagen.ast_validator import validate_c_source
from mutagen.compiler import compile_target
from mutagen.constants import DEFAULT_EXEC_TIMEOUT, DEFAULT_MODEL_GEMINI, DEFAULT_PROVIDER
from mutagen.executor import execute_payload
from mutagen.state import ProgramContext


class StructuralValidatorAgent(BaseAgent):
    def __init__(self, model_provider: str = DEFAULT_PROVIDER, model_name: str = DEFAULT_MODEL_GEMINI, compiler_path: str = "gcc", delivery_mode: str = "args", api_key: str = None, execution_timeout: int = DEFAULT_EXEC_TIMEOUT, sandbox: str = "none"):
        super().__init__("Structural Validator Agent", model_provider, model_name, api_key)
        self.compiler_path = compiler_path
        self.delivery_mode = delivery_mode
        self.execution_timeout = execution_timeout
        self.sandbox = sandbox

    async def process(self, context: ProgramContext) -> ProgramContext:
        context.logs.append("[StructuralValidatorAgent] Running structural validation checks...")

        patched_code = context.get_primary_patch()
        if not patched_code:
            context.logs.append("[StructuralValidatorAgent] No proposed patch found to validate.")
            context.verification_status = "REGRESSION_FAILED"
            return context

        # 1. Run Tree-sitter AST Pre-Check (C/C++ only)
        if context.language == "c":
            result = validate_c_source(patched_code)
            if not result.is_valid:
                err_msg = ", ".join(f"line {e.line}: {e.message}" for e in result.errors)
                try:
                    import time
                    os.makedirs("logs", exist_ok=True)
                    log_file = f"logs/ast_failure_raw_{int(time.time())}.log"
                    with open(log_file, "w", encoding="utf-8") as lf:
                        lf.write(f"--- AST VALIDATION FAILURE RAW PATCH DUMP ---\n{err_msg}\n\nRAW PATCH CONTENT:\n{patched_code}\n")
                    context.logs.append(f"[StructuralValidatorAgent] Raw patch dumped to {log_file}")
                except Exception:
                    pass
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
                err_msg = f"[StructuralValidatorAgent] Compilation of patched target failed: {e}"
                context.logs.append(err_msg)
                context.notepad.append(f"Validator: Compilation error on patch: {e}")
                context.verification_status = "REGRESSION_FAILED"
                return context

            # 3. Fire all reproduction crash payloads at the patched target
            active_crashes = [p for p in context.active_payloads if p.crash_type is not None]
            if not active_crashes:
                # No crashes were detected previously, so compile success is enough
                context.verification_status = "VERIFIED_SECURE"
                context.logs.append("[StructuralValidatorAgent] Verification passed (no active crashes were recorded).")
                context.notepad.append("Validator: Verification passed (no active crashes recorded).")
                return context

            current_sandbox = getattr(self, "sandbox", "none")
            if current_sandbox == "none" and context.sandboxed:
                current_sandbox = "docker"

            all_secured = True
            for crash in active_crashes:
                # For stdin mode, ensure the payload string is passed as input_data if args is set but input_data is empty
                input_data = crash.input_data
                if self.delivery_mode == "stdin" and not input_data and crash.args:
                    input_data = "\n".join(crash.args)

                # Bridge raw_bytes_hex → input_data for file/stdin mode (binary payloads)
                if crash.raw_bytes_hex and (not input_data or not str(input_data).strip()):
                    try:
                        input_data = bytes.fromhex(crash.raw_bytes_hex)
                    except ValueError:
                        pass

                res = execute_payload(
                    exe_path=exe_path,
                    args=crash.args,
                    input_data=input_data,
                    delivery_mode=self.delivery_mode,
                    timeout=self.execution_timeout,
                    sandbox=current_sandbox
                )

                # Check if it still crashes using the executor's oracle-resolved crashed flag
                is_still_crashing = res.get("crashed", False)
                if is_still_crashing:
                    fail_msg = f"Validator verification failed: Payload {crash.args} still triggered vulnerability (type: {res.get('crash_type')})."
                    context.logs.append(f"[StructuralValidatorAgent] {fail_msg}")
                    context.notepad.append(f"Validator: {fail_msg}")
                    all_secured = False
                    break

            if all_secured:
                context.verification_status = "VERIFIED_SECURE"
                context.logs.append("[StructuralValidatorAgent] Verification PASSED! The patch blocks all crash payloads.")
                context.notepad.append("Validator: Verification PASSED! All payloads blocked.")
            else:
                context.verification_status = "REGRESSION_FAILED"

        return context
