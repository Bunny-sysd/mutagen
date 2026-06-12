import subprocess
import os

def execute_payload(exe_path: str, args: list[str], timeout: int) -> dict:
    """
    Run the target program with the given arguments and check if it crashes.

    WHAT THIS DOES:
    - Launches the compiled program as a child process
    - Passes args as command-line arguments (supports multi-arg targets!)
    - Waits up to timeout seconds for it to finish (timeout = hung process)
    - Checks the return code:
        * Return code 0 = program ran fine (no crash)
        * Return code != 0 = something went wrong
        * On Windows, access violation = return code -1073741819
    """
    try:
        try:
            result = subprocess.run(
                [exe_path] + args,
                capture_output=True,
                text=True,
                timeout=timeout  # Kill if it hangs
            )
        except OSError as e:
            return {
                "crashed": False,
                "crash_type": f"OS_ERROR: {e}",
                "return_code": -1,
                "stdout": "",
                "stderr": str(e)
            }

        # --- CRASH DETECTION -----------------------------------------------
        # On Windows, an "Access Violation" (segfault equivalent)
        # returns -1073741819 (0xC0000005).
        crashed = False
        crash_type = "none"

        if result.returncode != 0:
            crashed = True
            
            # Windows NTSTATUS codes
            if result.returncode in (-1073741819, 3221225477):
                crash_type = "ACCESS_VIOLATION (Memory Corruption!)"
            elif result.returncode == -1073741676:
                crash_type = "STACK_OVERFLOW"
            elif result.returncode == -1073741571:
                crash_type = "STACK_BUFFER_OVERRUN"
            # POSIX Signals (usually negative return codes in Python subprocess)
            elif result.returncode == -11:
                crash_type = "SIGSEGV (Segmentation Fault)"
            elif result.returncode == -6:
                crash_type = "SIGABRT (Aborted)"
            elif result.returncode == -4:
                crash_type = "SIGILL (Illegal Instruction)"
            elif result.returncode == -8:
                crash_type = "SIGFPE (Floating Point Exception)"
            elif result.returncode == -7:
                crash_type = "SIGBUS (Bus Error)"
            elif result.returncode < 0:
                crash_type = f"SIGNAL_{abs(result.returncode)}"
            else:
                # Normal non-zero exit code (e.g. return 1;) is NOT a memory corruption!
                crashed = False
                crash_type = "none"

        return {
            "crashed": crashed,
            "crash_type": crash_type,
            "return_code": result.returncode,
            "stdout": result.stdout[:200] if result.stdout else "",
            "stderr": result.stderr[:200] if result.stderr else "",
        }

    except subprocess.TimeoutExpired:
        return {
            "crashed": True,
            "crash_type": "TIMEOUT (possible infinite loop / hang)",
            "return_code": -1,
            "stdout": "",
            "stderr": "Process killed after timeout",
        }
