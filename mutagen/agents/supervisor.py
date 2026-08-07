
import os
from mutagen.agents.base import BaseAgent
from mutagen.compiler import compile_target
from mutagen.constants import DEFAULT_EXEC_TIMEOUT, DEFAULT_MODEL_GEMINI, DEFAULT_PROVIDER
from mutagen.executor import execute_payload
from mutagen.state import ProgramContext


class FuzzingSupervisorAgent(BaseAgent):
    def __init__(self, model_provider: str = DEFAULT_PROVIDER, model_name: str = DEFAULT_MODEL_GEMINI, compiler_path: str = "gcc", delivery_mode: str = "args", api_key: str = None, execution_timeout: int = DEFAULT_EXEC_TIMEOUT, sandbox: str = "none"):
        super().__init__("Fuzzing Supervisor Agent", model_provider, model_name, api_key)
        self.compiler_path = compiler_path
        self.delivery_mode = delivery_mode
        self.execution_timeout = execution_timeout
    async def process(self, context: ProgramContext) -> ProgramContext:
        context.logs.append("[FuzzingSupervisorAgent] Compiling target file...")

        # 1. Extract target function from triage vulnerabilities if available
        target_vuln_func = None
        if context.vulnerabilities:
            v0 = context.vulnerabilities[0]
            from mutagen.reachability_checker import extract_vulnerable_function_name
            target_vuln_func = extract_vulnerable_function_name(context.target_path, v0.line_number)

        try:
            exe_path = compile_target(context.target_path, self.compiler_path, vuln_function=target_vuln_func)
            if exe_path and os.path.exists(exe_path):
                context.logs.append(f"[FuzzingSupervisorAgent] Compiled target successfully to: {exe_path}")
            else:
                setattr(context, "reachability_status", "UNREACHABLE_NO_TARGET")
                setattr(context, "reachability_message", f"Static finding in '{target_vuln_func or 'target'}' could not be dynamically verified: no build target exercises this code path")
                context.logs.append(f"[FuzzingSupervisorAgent] No build target reaches vulnerable code path '{target_vuln_func}'")
                return context
        except Exception as e:
            context.logs.append(f"[FuzzingSupervisorAgent] Compilation failed: {e}")
            return context

        # 2. Run synthesized payloads against the compiled target
        current_sandbox = getattr(self, "sandbox", "none")
        if current_sandbox == "none" and context.sandboxed:
            current_sandbox = "docker"

        context.logs.append(f"[FuzzingSupervisorAgent] Executing {len(context.active_payloads)} payloads using delivery mode: {self.delivery_mode} (Sandbox: {current_sandbox})...")
        for payload in context.active_payloads:
            # For stdin mode, ensure the payload string is passed as input_data if args is set but input_data is empty
            input_data = payload.input_data
            if self.delivery_mode == "stdin" and not input_data and payload.args:
                input_data = "\n".join(payload.args)

            # Bridge raw_bytes_hex → input_data for file/stdin mode (binary payloads)
            if payload.raw_bytes_hex and (not input_data or not str(input_data).strip()):
                try:
                    input_data = bytes.fromhex(payload.raw_bytes_hex)
                except ValueError:
                    pass

            result = execute_payload(
                exe_path=exe_path,
                args=payload.args,
                input_data=input_data,
                delivery_mode=self.delivery_mode,
                timeout=self.execution_timeout,
                sandbox=current_sandbox
            )

            # Map execution results & verifiable container metadata
            payload.exit_code = result.get("return_code")
            payload.stdout = result.get("stdout", "")
            payload.stderr = result.get("stderr", "")
            payload.container_id = result.get("container_id", "")
            payload.container_image = result.get("container_image", "")
            payload.container_image_digest = result.get("container_image_digest", "")

            # If WDAC/AppLocker blocked, result might contain a DELIVERY_ERROR:
            exec_err = result.get("crash_type", "")
            if "DELIVERY_ERROR" in str(exec_err) or "blocked" in str(payload.stderr).lower():
                context.logs.append(f"[FuzzingSupervisorAgent] Execution blocked/error for payload {payload.args}: {exec_err} | stderr: {payload.stderr}")

            # Identify crash type using the executor's oracle-resolved crashed flag
            if result.get("crashed"):
                payload.crash_type = result.get("crash_type")
                context.logs.append(f"[FuzzingSupervisorAgent] Vulnerability triggered! Type: {payload.crash_type} for args: {payload.args}")
            else:
                payload.crash_type = None
                context.logs.append(f"[FuzzingSupervisorAgent] Payload {payload.args} returned {payload.exit_code} (No vulnerability detected)")

        return context
