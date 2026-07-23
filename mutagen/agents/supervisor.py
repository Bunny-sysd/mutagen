
from mutagen.agents.base import BaseAgent
from mutagen.compiler import compile_target
from mutagen.executor import execute_payload
from mutagen.state import ProgramContext


class FuzzingSupervisorAgent(BaseAgent):
    def __init__(self, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", compiler_path: str = "gcc", delivery_mode: str = "args", api_key: str = None):
        super().__init__("Fuzzing Supervisor Agent", model_provider, model_name, api_key)
        self.compiler_path = compiler_path
        self.delivery_mode = delivery_mode

    async def process(self, context: ProgramContext) -> ProgramContext:
        context.logs.append("[FuzzingSupervisorAgent] Compiling target file...")

        # 1. Compile target executable
        try:
            exe_path = compile_target(context.target_path, self.compiler_path)
            context.logs.append(f"[FuzzingSupervisorAgent] Compiled target successfully to: {exe_path}")
        except Exception as e:
            context.logs.append(f"[FuzzingSupervisorAgent] Compilation failed: {e}")
            return context

        # 2. Run synthesized payloads against the compiled target
        context.logs.append(f"[FuzzingSupervisorAgent] Executing {len(context.active_payloads)} payloads using delivery mode: {self.delivery_mode}...")
        for payload in context.active_payloads:
            # For stdin mode, ensure the payload string is passed as input_data if args is set but input_data is empty
            input_data = payload.input_data
            if self.delivery_mode == "stdin" and not input_data and payload.args:
                input_data = "\n".join(payload.args)

            result = execute_payload(
                exe_path=exe_path,
                args=payload.args,
                input_data=input_data,
                delivery_mode=self.delivery_mode,
                timeout=5
            )

            # Map execution results
            payload.exit_code = result.get("return_code")
            payload.stdout = result.get("stdout", "")
            payload.stderr = result.get("stderr", "")

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
