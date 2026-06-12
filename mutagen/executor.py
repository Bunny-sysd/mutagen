import subprocess
import os

def execute_payload(exe_path: str, args: list[str], input_data: str, delivery_mode: str, timeout: int) -> dict:
    """
    Run the target program with the given arguments and check if it crashes.

    WHAT THIS DOES:
    - Launches the compiled program as a child process
    - Passes args as command-line arguments (for args mode) or pipes input (for stdin/tcp mode)
    - Waits up to timeout seconds for it to finish (timeout = hung process)
    - Checks the return code:
        * Return code 0 = program ran fine (no crash)
        * Return code != 0 = something went wrong
        * On Windows, access violation = return code -1073741819
    """
    try:
        try:
            if delivery_mode == "args":
                result = subprocess.run(
                    [exe_path] + args,
                    capture_output=True,
                    text=True,
                    timeout=timeout  # Kill if it hangs
                )
            elif delivery_mode == "stdin":
                result = subprocess.run(
                    [exe_path],
                    input=input_data,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            elif delivery_mode.startswith("tcp:"):
                port = int(delivery_mode.split(":")[1])
                import socket
                import time
                process = subprocess.Popen(
                    [exe_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                time.sleep(0.5) # Wait for server to start
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # Use standard loopback address safely
                    sock.connect(("127.0.0.1", port))
                    sock.sendall(input_data.encode("utf-8"))
                    sock.close()
                except Exception:
                    pass # Might fail if process died immediately
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                    result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    raise subprocess.TimeoutExpired(process.args, timeout, output=stdout, stderr=stderr)
            else:
                raise ValueError(f"Unknown delivery mode: {delivery_mode}")
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

        # --- ORACLE DETECTION -----------------------------------------------
        # Even if the program didn't physically crash, scan console outputs
        # for signatures indicating a successful logical exploit/bypass.
        if not crashed:
            stdout_lower = (result.stdout or "").lower()
            stderr_lower = (result.stderr or "").lower()
            
            logical_indicators = [
                "access granted",
                "privileges acquired",
                "admin privileges",
                "flag{",
                "root:",
                "uid=0",
                "systeminfo",
                "cmd.exe",
                "/bin/sh",
                "vuln_triggered",
                "exploit_success",
                "authenticated as admin"
            ]
            
            for indicator in logical_indicators:
                if indicator in stdout_lower or indicator in stderr_lower:
                    crashed = True
                    crash_type = f"LOGICAL_EXPLOIT (Matched signature: '{indicator}')"
                    break

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
