from mutagen.agents.base import BaseAgent
from mutagen.state import ProgramContext, CrashPayload
from mutagen.compiler import compile_target
from mutagen.executor import execute_payload
import os

class FuzzingSupervisorAgent(BaseAgent):
    def __init__(self, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", compiler_path: str = "gcc", api_key: str = None):
        super().__init__("Fuzzing Supervisor Agent", model_provider, model_name, api_key)
        self.compiler_path = compiler_path

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
        context.logs.append(f"[FuzzingSupervisorAgent] Executing {len(context.active_payloads)} payloads...")
        for payload in context.active_payloads:
            result = execute_payload(
                exe_path=exe_path,
                args=payload.args,
                input_data=payload.input_data,
                delivery_mode="args",
                timeout=5
            )
            
            # Map execution results
            payload.exit_code = result.get("return_code")
            payload.stdout = result.get("stdout", "")
            payload.stderr = result.get("stderr", "")
            
            # Identify crash type
            return_code = payload.exit_code
            
            # If WDAC/AppLocker blocked, result might contain a DELIVERY_ERROR:
            exec_err = result.get("crash_type", "")
            if "DELIVERY_ERROR" in str(exec_err) or "blocked" in str(payload.stderr).lower():
                context.logs.append(f"[FuzzingSupervisorAgent] Execution blocked/error for payload {payload.args}: {exec_err} | stderr: {payload.stderr}")
                
            if return_code != 0 and return_code is not None and return_code != -1:
                # Identify crash signature
                if return_code in (-1073741819, 3221225477):
                    payload.crash_type = "ACCESS_VIOLATION"
                elif return_code in (-1073740940, 3221226356):
                    payload.crash_type = "HEAP_CORRUPTION"
                elif return_code == -1073741676:
                    payload.crash_type = "STACK_OVERFLOW"
                elif return_code == -1073741571:
                    payload.crash_type = "STACK_BUFFER_OVERRUN"
                elif return_code < 0:
                    payload.crash_type = f"SIGNAL_{abs(return_code)}"
                else:
                    payload.crash_type = "CRASH"
                
                context.logs.append(f"[FuzzingSupervisorAgent] Crash detected! Type: {payload.crash_type}, Code: {return_code} for args: {payload.args}")
            else:
                payload.crash_type = None
                context.logs.append(f"[FuzzingSupervisorAgent] Payload {payload.args} returned {return_code} (No crash detected)")

        return context
