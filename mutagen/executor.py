import subprocess
import os

def execute_payload(exe_path: str, args: list[str], input_data, delivery_mode: str, timeout: int) -> dict:
    # Coerce input_data to string
    if isinstance(input_data, dict):
        lowered_keys = {k.lower(): v for k, v in input_data.items()}
        if "key" in lowered_keys and "value" in lowered_keys:
            input_data = f"{lowered_keys['key']}={lowered_keys['value']}"
        else:
            parts = []
            for k, v in input_data.items():
                parts.append(f"{k}={v}")
            input_data = "\n".join(parts)
    elif isinstance(input_data, list):
        input_data = "\n".join(str(x) for x in input_data)
    elif input_data is None:
        input_data = ""
    else:
        input_data = str(input_data)

    # Coerce args elements to strings
    if isinstance(args, list):
        args = [str(a) for a in args]
    else:
        args = [str(args)] if args is not None else []

    # Sanitize null bytes from args in args-mode.
    # Windows CreateProcess uses null-terminated strings for CLI arguments,
    # so embedded \x00 bytes cause a ValueError at the OS level.
    # In stdin/tcp mode null bytes are fine (binary data over a pipe/socket).
    if delivery_mode == "args":
        args = [a.replace('\x00', '') for a in args]

    # Strip accidental program name (argv[0]) placeholder prepended by the LLM
    if args and len(args) > 1:
        first_arg = args[0].strip().lower()
        exe_name = os.path.basename(exe_path).lower()
        exe_name_no_ext = os.path.splitext(exe_name)[0]
        placeholders = {
            "program", "./program", "a.out", "./a.out", "target", "./target",
            exe_name, f"./{exe_name}", exe_name_no_ext, f"./{exe_name_no_ext}"
        }
        if first_arg in placeholders:
            args = args[1:]


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
        except (OSError, ValueError) as e:
            # OSError  — executable not found, permission denied, etc.
            # ValueError — embedded null character in args (Windows-only);
            #              this payload cannot be tested via CLI args on Windows.
            return {
                "crashed": False,
                "crash_type": f"DELIVERY_ERROR: {e}",
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
            # Rust panic exit code
            elif result.returncode == 101:
                crash_type = "RUST_PANIC (Safety Violation!)"
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
        # for signatures indicating a successful logical exploit/bypass OR
        # a real memory corruption that was caught/masked by the harness.
        stdout_lower = (result.stdout or "").lower()
        stderr_lower = (result.stderr or "").lower()
        combined_lower = stdout_lower + stderr_lower

        if not crashed:
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
                if indicator in combined_lower:
                    crashed = True
                    crash_type = f"LOGICAL_EXPLOIT (Matched signature: '{indicator}')"
                    break

        # --- HEAP/MEMORY CORRUPTION ORACLE ----------------------------------
        # Detect real memory corruption events that the harness caught and
        # reported before they could raise a signal (e.g. SASL_BUFOVER after
        # a strcpy overflow, asan reports, glibc heap corruption messages).
        # These ARE real vulnerabilities even if return code is 0 or 1.
        if not crashed:
            heap_corruption_signatures = [
                # Harness-level overflow detection
                "sasl_bufover",
                "bufover",
                "buffer overflow",
                "heap buffer overflow",
                # ASan / UBSan runtime reports
                "heap-buffer-overflow",
                "stack-buffer-overflow",
                "use-after-free",
                "double-free",
                "memory corruption",
                "addresssanitizer",
                "ubsanitizer",
                # glibc / CRT heap corruption
                "corrupted size vs. prev_size",
                "malloc(): corrupted top size",
                "free(): invalid next size",
                "double free or corruption",
                "invalid pointer",
                # Windows CRT
                "heap corruption detected",
                "invalid heap pointer",
                "_crtisvalidheappointer",
            ]
            for sig in heap_corruption_signatures:
                if sig in combined_lower:
                    crashed = True
                    crash_type = f"HEAP_CORRUPTION (Caught overflow signature: '{sig}')"
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
