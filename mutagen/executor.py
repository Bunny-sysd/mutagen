import os
import subprocess

_DOCKER_WARNED = False

def _check_docker_functional() -> bool:
    global _DOCKER_WARNED
    try:
        res = subprocess.run(["docker", "ps"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            return True
    except Exception:
        pass

    if not _DOCKER_WARNED:
        try:
            from rich.console import Console
            console = Console(force_terminal=True, force_jupyter=False)
            console.print("[yellow][!] Warning: Docker sandbox requested but Docker is not installed or daemon is offline.[/yellow]")
            console.print("[yellow]  Falling back to host direct execution.[/yellow]")
        except Exception:
            pass
        _DOCKER_WARNED = True
    return False

def execute_payload(exe_path: str, args: list[str], input_data, delivery_mode: str, timeout: int, sandbox: str = "none") -> dict:
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
    if args:
        first_arg = args[0].strip().replace("\\", "/").lower()
        exe_clean = os.path.basename(exe_path).lower()
        exe_name_no_ext = os.path.splitext(exe_clean)[0]
        
        is_placeholder = (
            first_arg in ("program", "./program", "a.out", "./a.out", "target", "./target", 
                          "fuzzer_target", "./fuzzer_target", "fuzzer", "./fuzzer") or
            first_arg == exe_clean or
            first_arg == f"./{exe_clean}" or
            first_arg == exe_name_no_ext or
            first_arg == f"./{exe_name_no_ext}" or
            first_arg.endswith("/" + exe_clean) or
            first_arg.endswith("/" + exe_name_no_ext)
        )
        if is_placeholder:
            args = args[1:]

    # --- SANDBOX COMMAND CONSTRUCT ------------------------------------------
    if exe_path.lower().endswith(".py"):
        import sys
        run_cmd = [sys.executable, exe_path]
    else:
        run_cmd = [exe_path]
    if sandbox == "docker" and _check_docker_functional():
        abs_exe_path = os.path.abspath(exe_path)
        exe_dir = os.path.dirname(abs_exe_path)
        exe_name = os.path.basename(abs_exe_path)
        image = os.environ.get("MUTAGEN_SANDBOX_IMAGE", "ubuntu:latest")

        docker_args = [
            "docker", "run", "--rm", "-i",
            "--memory=512m",
            "--cpus=1.0",
            "-v", f"{exe_dir}:/target:ro",
            "-w", "/target"
        ]

        if delivery_mode.startswith("tcp:"):
            port = int(delivery_mode.split(":")[1])
            docker_args.extend(["-p", f"{port}:{port}"])
        else:
            docker_args.append("--network=none")

        docker_args.extend([image, f"./{exe_name}"])
        run_cmd = docker_args


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
        env = os.environ.copy()
        workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        existing_pythonpath = env.get("PYTHONPATH", "")
        if existing_pythonpath:
            env["PYTHONPATH"] = workspace_dir + os.pathsep + existing_pythonpath
        else:
            env["PYTHONPATH"] = workspace_dir

        try:
            if delivery_mode == "args":
                result = subprocess.run(
                    run_cmd + args,
                    capture_output=True,
                    text=True,
                    timeout=timeout,  # Kill if it hangs
                    env=env
                )
            elif delivery_mode == "stdin":
                # Convert string representations of escapes to raw bytes
                if isinstance(input_data, str):
                    try:
                        input_bytes = input_data.encode('utf-8').decode('unicode_escape').encode('latin-1')
                    except Exception:
                        input_bytes = input_data.encode('utf-8')
                else:
                    input_bytes = input_data or b""

                result = subprocess.run(
                    run_cmd,
                    input=input_bytes,
                    capture_output=True,
                    timeout=timeout,
                    env=env
                )
            elif delivery_mode.startswith("tcp:"):
                # Convert string representations of escapes to raw bytes
                if isinstance(input_data, str):
                    try:
                        input_bytes = input_data.encode('utf-8').decode('unicode_escape').encode('latin-1')
                    except Exception:
                        input_bytes = input_data.encode('utf-8')
                else:
                    input_bytes = input_data or b""

                port = int(delivery_mode.split(":")[1])
                import socket
                import time
                process = subprocess.Popen(
                    run_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env
                )
                time.sleep(0.5) # Wait for server to start
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # Use standard loopback address safely
                    sock.connect(("127.0.0.1", port))
                    sock.sendall(input_bytes)
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

            # Ensure outputs are decodable strings for the fuzzing oracle checks
            if hasattr(result, "stdout") and isinstance(result.stdout, bytes):
                result.stdout = result.stdout.decode("utf-8", errors="ignore")
            if hasattr(result, "stderr") and isinstance(result.stderr, bytes):
                result.stderr = result.stderr.decode("utf-8", errors="ignore")
        except (OSError, ValueError) as e:
            # OSError  — executable not found, permission denied, etc.
            # ValueError — embedded null character in args (Windows-only);
            #              this payload cannot be tested via CLI args on Windows.
            return {
                "crashed": False,
                "crash_type": f"DELIVERY_ERROR: {e}",
                "return_code": -1,
                "stdout": "",
                "stderr": str(e),
                "coverage": []
            }

        # --- PARSE COVERAGE FEEDBACK ---------------------------------------
        coverage = []
        if result.stdout:
            import re
            cov_match = re.search(r'__MUTAGEN_COV__:([0-9,]*)\b', result.stdout)
            if cov_match:
                try:
                    raw_ids = cov_match.group(1)
                    if raw_ids:
                        coverage = [int(x) for x in raw_ids.split(",") if x]
                except Exception:
                    pass
                # Strip the coverage line from stdout to keep stdout clean
                cleaned_stdout = re.sub(r'\n?__MUTAGEN_COV__:[0-9,]*\b\n?', '\n', result.stdout).strip()
                result.stdout = cleaned_stdout

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
            elif result.returncode in (-1073740940, 3221226356):
                crash_type = "HEAP_CORRUPTION (Double Free / Heap Corruption!)"
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

        # Strip the input data and arguments from the output to prevent false matches
        # when the program simply echoes the input back in logs or error messages.
        clean_output = combined_lower
        if input_data:
            clean_output = clean_output.replace(input_data.lower(), "")
        for arg in args:
            clean_output = clean_output.replace(arg.lower(), "")

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
                "authenticated as admin",
                "is not recognized as an internal or external command",
                "operable program or batch file",
                "command not found",
                "no such file or directory",
                "directory nonexistent",
                "pwned",
                "pwn"
            ]

            for indicator in logical_indicators:
                if indicator in clean_output:
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
                    # Globally differentiate safe handled program exit (rc=1, typical for safe error/assert exit)
                    # from unhandled crash states when checking soft signatures.
                    # Hard indicators (asan/ubsan/corrupted size) remain crashes regardless of rc.
                    is_hard_sanitizer = any(k in sig for k in ["addresssanitizer", "ubsanitizer", "corrupted", "malloc()", "free()", "double free", "invalid pointer", "heap corruption detected"])
                    if is_hard_sanitizer or (result.returncode != 0 and result.returncode != 1):
                        crashed = True
                        crash_type = f"HEAP_CORRUPTION (Caught overflow signature: '{sig}')"
                        break
                    elif sig in ["sasl_bufover", "bufover", "buffer overflow", "heap buffer overflow"]:
                        # If a diagnostic string was printed but it exited with controlled code 1,
                        # this is a safe, handled mitigation exit, NOT a crash.
                        crashed = False
                        crash_type = "none"

        return {
            "crashed": crashed,
            "crash_type": crash_type,
            "return_code": result.returncode,
            "stdout": result.stdout[:200] if result.stdout else "",
            "stderr": result.stderr[:200] if result.stderr else "",
            "coverage": coverage,
        }

    except subprocess.TimeoutExpired:
        return {
            "crashed": True,
            "crash_type": "TIMEOUT (possible infinite loop / hang)",
            "return_code": -1,
            "stdout": "",
            "stderr": "Process killed after timeout",
            "coverage": []
        }
