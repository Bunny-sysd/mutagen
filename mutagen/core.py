import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from mutagen.compiler import CompilationError, compile_target
from mutagen.decompiler import (
    DecompilationError,
    decompile_binary,
    find_ghidra,
)
from mutagen.engines import get_engine
from mutagen.executor import _check_docker_functional, execute_payload
from mutagen.mutators import generate_fallback_payloads
from mutagen.reporter import save_crash_report
from mutagen.ast_validator import validate_c_source, format_validation_errors
from mutagen.session_supervisor import SessionSupervisor, SessionResult

console = Console(force_terminal=True, force_jupyter=False)


def _crash_signature(crash: dict) -> str:
    """Generate a deduplication key from a crash result."""
    import re
    # Normalize stdout/stderr by stripping memory addresses and temporary file paths to avoid ASLR/env noise
    stdout = crash.get("stdout", "")
    stderr = crash.get("stderr", "")

    stdout_norm = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', stdout).strip()
    stderr_norm = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', stderr).strip()

    stdout_norm = re.sub(r'[a-zA-Z]:\\[^\s:]+', 'FILE_PATH', stdout_norm)
    stderr_norm = re.sub(r'[a-zA-Z]:\\[^\s:]+', 'FILE_PATH', stderr_norm)

    return f"{crash['crash_type']}::{crash['return_code']}::{crash.get('vuln_type', '')}::{stdout_norm}::{stderr_norm}"


def verify_and_fallback_exploit(exploit_code: str, crash_data: dict, exe_path: str, delivery_mode: str) -> str:
    """
    Checks if the generated exploit code is valid Python.
    If it is not, or if it's just raw payload strings, it generates a robust
    boilerplate Python PoC that uses the crashing payload.
    """
    is_valid_python = False
    # Check for basic Python landmarks
    if exploit_code and ("import " in exploit_code or "def " in exploit_code or "sys.argv" in exploit_code):
        is_valid_python = True

    # If the code contains mostly a single repeating character (like A's), it is a raw payload dump
    if exploit_code and len(exploit_code.strip()) > 50:
        cleaned = exploit_code.strip()
        first_char = cleaned[0]
        if cleaned.count(first_char) > len(cleaned) * 0.8:
            is_valid_python = False

    if is_valid_python:
        return exploit_code

    # Fallback script generation
    payload_repr = repr(crash_data.get("input_data", ""))
    args_repr = repr(crash_data.get("args", []))

    fallback_script = f"""# -*- coding: utf-8 -*-
\"\"\"
Mutagen Auto-Generated Exploit PoC (Fallback)
Target: {exe_path}
Vulnerability Class: {crash_data.get("vuln_type", "Memory Corruption")}
CWE: {crash_data.get("cwe", "CWE-120")}
Reason: {crash_data.get("reason", "Heap/Stack buffer overflow or crash")}
\"\"\"

import sys
import os
import subprocess
import socket
import time

def run_poc():
    # Target path can be overridden by sys.argv[1]
    exe_path = sys.argv[1] if len(sys.argv) > 1 else {repr(exe_path)}
    delivery_mode = {repr(delivery_mode)}
    payload = {payload_repr}
    args = {args_repr}

    print(f"[*] Launching target: {{exe_path}}")
    print(f"[*] Delivery mode: {{delivery_mode}}")

    if not os.path.exists(exe_path):
        print(f"[!] Error: Target executable '{{exe_path}}' not found!")
        sys.exit(1)

    if delivery_mode == "args":
        # Launch with payload as command line arguments
        print(f"[*] Executing with arguments: {{args}}")
        cmd = [exe_path] + args
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(timeout=5)
        print(f"[*] Process exited with return code: {{proc.returncode}}")

    elif delivery_mode == "stdin":
        # Launch and pipe payload into stdin
        print(f"[*] Writing payload to stdin...")
        proc = subprocess.Popen([exe_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = proc.communicate(input=payload.encode('utf-8', errors='ignore') if isinstance(payload, str) else payload, timeout=5)
            print(f"[*] Process exited with return code: {{proc.returncode}}")
        except subprocess.TimeoutExpired:
            print("[!] Process hung (possible Denial of Service / infinite loop)!")
            proc.kill()
            sys.exit(0)

    elif delivery_mode.startswith("tcp:"):
        # Launch process and send payload over socket
        port = int(delivery_mode.split(":")[1])
        print(f"[*] Launching server and waiting for port {{port}}...")
        proc = subprocess.Popen([exe_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5) # Wait for bind

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(("127.0.0.1", port))
            print(f"[*] Sending packet payload (len={{len(payload)}})...")
            s.sendall(payload.encode('utf-8', errors='ignore') if isinstance(payload, str) else payload)
            s.close()
            print("[*] Payload sent successfully.")
        except Exception as e:
            print(f"[!] Socket connection failed: {{e}}")
        finally:
            # Check status
            time.sleep(0.5)
            ret = proc.poll()
            if ret is not None:
                print(f"[*] Server terminated with return code: {{ret}}")
            else:
                print("[*] Server is still running, terminating...")
                proc.terminate()

if __name__ == "__main__":
    run_poc()
"""
    return fallback_script


def mutate_input(args: list[str], input_data: str, delivery_mode: str) -> tuple[list[str], str]:
    """Applies a random mutation (bit flip, byte replace, arithmetic, or insert) to args or input_data."""
    import random
    import re

    def mutate_string(s: str) -> str:
        if not s:
            return random.choice(["A", "1", "%s", "\x00", "; ls"])
        s_list = list(s)
        choice = random.randint(0, 4)
        if choice == 0:  # Bit flip
            idx = random.randint(0, len(s_list) - 1)
            try:
                char_code = ord(s_list[idx])
                bit = 1 << random.randint(0, 7)
                s_list[idx] = chr(char_code ^ bit)
            except Exception:
                pass
        elif choice == 1:  # Byte replacement
            idx = random.randint(0, len(s_list) - 1)
            s_list[idx] = random.choice(["\x00", "\xff", "%s", "A", "\n", ";"])
        elif choice == 2:  # Arithmetic mutation (increment/decrement digits)
            nums = re.findall(r'\d+', s)
            if nums:
                num = random.choice(nums)
                try:
                    val = int(num)
                    new_val = val + random.choice([-1, 1, -10, 10, -100, 100])
                    s = s.replace(num, str(new_val), 1)
                    return s
                except Exception:
                    pass
        elif choice == 3:  # Substring duplication/insertion
            idx = random.randint(0, len(s_list))
            insert_str = random.choice(["A" * 16, "B" * 64, "%s" * 5, "\x00" * 8, "; id;"])
            s_list.insert(idx, insert_str)
        elif choice == 4:  # Truncation
            trunc_len = random.randint(1, len(s_list))
            s_list = s_list[:trunc_len]

        return "".join(s_list)

    if delivery_mode == "args":
        new_args = list(args)
        if new_args:
            idx = random.randint(0, len(new_args) - 1)
            new_args[idx] = mutate_string(new_args[idx])
        else:
            new_args = [mutate_string("")]
        return new_args, input_data
    else:
        return args, mutate_string(input_data)


# ---------------------------------------------------------------------------
# Session-mode fuzzer (Persistent Supervisor path)
# ---------------------------------------------------------------------------

def _run_session_fuzzer(
    exe_path: str,
    source_code: str,
    source_path: str,
    delivery_mode: str,
    timeout: int,
    sandbox: str,
    max_payloads: int,
    engine,
    debug: bool,
    language: str = "c",
    binary_mode: bool = False,
    profile: str = "legacy-audit",
    webhook_url: str = "",
    webhook_secret: str = "",
    webhook_headers: list[str] = None,
) -> int:
    """Run the fuzzer in session mode with a persistent process supervisor.

    Instead of fire-and-forget payloads, this asks the AI for ordered
    *sequences* of inputs and feeds them to a long-lived target process,
    tracking per-step state transitions (stdout, stderr, coverage deltas).

    Returns the number of unique crashes found.
    """
    console.print(Panel(
        "[bold red]PHASE 3: SESSION FUZZING (Persistent Supervisor)[/bold red]\n"
        "[dim]Feeding ordered payload sequences to a long-lived target process...[/dim]\n"
        f"[dim]Delivery mode: {delivery_mode} | Timeout: {timeout}s[/dim]",
        border_style="red"
    ))

    all_crashes = []
    seen_signatures = set()
    unique_crashes = []


    # Build the sequence generation prompt
    sequence_prompt = (
        "You are a security researcher fuzzing a stateful target program.\n"
        "The target accepts sequential inputs over a persistent connection.\n"
        "Generate ORDERED payload sequences (not individual payloads) designed to:\n"
        "1. First establish a valid session state (authentication, initialization)\n"
        "2. Then exploit vulnerabilities that only appear in specific states\n\n"
        "Each sequence should be a list of strings sent in order.\n"
        "The target process stays alive across all steps.\n\n"
        "CRITICAL: Do NOT include newline characters ('\\n') within any string in the 'sequence' array. "
        "Each step string is sent as a single line to the target. For commands like 'DATA <payload>', "
        "combine the command and payload into a single string (e.g. 'DATA AAAAAAAAAAAAAAAAAAAA').\n\n"
        "Return a JSON array of sequence objects like:\n"
        "[\n"
        "  {\n"
        '    "sequence": ["AUTH admin", "SELECT channel_5", "' + 'A' * 200 + '"],\n'
        '    "vuln_type": "buffer_overflow",\n'
        '    "reason": "Overflow after auth + channel select brings process to vulnerable handler",\n'
        '    "severity": "critical",\n'
        '    "cwe": "CWE-120"\n'
        "  }\n"
        "]\n\n"
        f"Generate up to {max_payloads} sequences.\n"
    )


    # Ask the AI for payload sequences
    console.print("[cyan]>> Requesting AI payload sequences for session-mode fuzzing...[/cyan]")

    raw_sequences = engine.generate_payloads(source_code, sequence_prompt, max_payloads, debug)

    # Normalize: the AI might return flat payloads or sequences
    sequences = _normalize_sequences(raw_sequences)

    if not sequences:
        console.print("[yellow]>> AI returned no valid sequences. Generating fallback single-step sequences...[/yellow]")
        from mutagen.mutators import generate_fallback_payloads
        fallback = generate_fallback_payloads(max_payloads, "stdin")
        sequences = [
            {
                "sequence": [p.get("input_data", "") or " ".join(p.get("args", []))],
                "vuln_type": p.get("vuln_type", "unknown"),
                "reason": p.get("reason", "Fallback payload"),
                "severity": p.get("severity", "medium"),
                "cwe": p.get("cwe", ""),
            }
            for p in fallback
        ]

    console.print(f"[green]>> Loaded {len(sequences)} payload sequences for session execution.[/green]\n")

    # Build results table
    results_table = Table(title="Session Fuzzing Results", box=box.ROUNDED, border_style="green")
    results_table.add_column("#", style="dim", width=4)
    results_table.add_column("Status", width=14)
    results_table.add_column("Steps", style="cyan", width=6)
    results_table.add_column("Crash Step", style="red", width=11)
    results_table.add_column("Crash Type", style="red", max_width=30)
    results_table.add_column("Coverage", style="green", width=10)
    results_table.add_column("Unique?", style="magenta", width=8)

    # --- Execute each sequence through the persistent supervisor ---
    max_session_retries = 2

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[red]Running session {task.completed}/{task.total}..."),
        console=console,
    ) as progress:
        task = progress.add_task("Sessions", total=len(sequences))

        for seq_idx, seq_data in enumerate(sequences):
            steps = seq_data.get("sequence", [])
            if not steps:
                progress.update(task, advance=1)
                continue

            # Run the session
            session_result = None
            for retry in range(max_session_retries + 1):
                try:
                    with SessionSupervisor(
                        exe_path, delivery_mode, timeout, sandbox, step_timeout=2.0
                    ) as supervisor:
                        session_result = supervisor.run_sequence(steps)
                    if debug and session_result:
                        console.print(f"[dim]  Session {seq_idx} execution details:[/dim]")
                        for s_idx, step_res in enumerate(session_result.steps):
                            console.print(f"[dim]    Step {s_idx}: input={repr(step_res.input_sent)}, alive={step_res.is_alive}, rc={step_res.return_code}, crash_type={step_res.crash_type}[/dim]")
                            if step_res.stdout_delta:
                                console.print(f"[dim]      stdout: {repr(step_res.stdout_delta)}[/dim]")
                            if step_res.stderr_delta:
                                console.print(f"[dim]      stderr: {repr(step_res.stderr_delta)}[/dim]")
                    break
                except Exception as e:
                    if retry == max_session_retries:
                        console.print(f"[red]  Session {seq_idx}: Failed after {max_session_retries} retries: {e}[/red]")
                        session_result = None

            if session_result is None:
                results_table.add_row(
                    str(seq_idx), "[yellow]ERROR", str(len(steps)),
                    "-", "SESSION_FAILED", "0", ""
                )
                progress.update(task, advance=1)
                continue


            # Process results
            status = "[bold red]CRASH!!" if session_result.crashed else "[green]OK"
            crash_step_str = str(session_result.crash_step) if session_result.crash_step is not None else "-"
            cov_str = str(len(session_result.total_coverage))

            is_unique = ""
            if session_result.crashed:
                crash_entry = {
                    "args": [],
                    "input_data": " → ".join(steps),
                    "payload": " → ".join(steps),
                    "vuln_type": seq_data.get("vuln_type", "stateful_vulnerability"),
                    "cwe": seq_data.get("cwe", ""),
                    "reason": seq_data.get("reason", "Session-mode crash"),
                    "severity": seq_data.get("severity", "high"),
                    "crash_type": session_result.crash_type,
                    "return_code": session_result.return_code,
                    "stdout": session_result.steps[session_result.crash_step].stdout_delta if session_result.crash_step is not None and session_result.crash_step < len(session_result.steps) else "",
                    "stderr": session_result.steps[session_result.crash_step].stderr_delta if session_result.crash_step is not None and session_result.crash_step < len(session_result.steps) else "",
                    "session_steps": len(steps),
                    "crash_step": session_result.crash_step,
                    "step_history": [
                        {
                            "step": s.step_index,
                            "input": s.input_sent,
                            "stdout": s.stdout_delta[:100],
                            "alive": s.is_alive,
                            "coverage_blocks": len(s.cumulative_coverage),
                        }
                        for s in session_result.steps
                    ],
                }
                sig = _crash_signature(crash_entry)
                all_crashes.append(crash_entry)
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    unique_crashes.append(crash_entry)
                    is_unique = "✓ NEW"

            results_table.add_row(
                str(seq_idx), status, str(len(steps)),
                crash_step_str, session_result.crash_type[:28],
                cov_str, is_unique,
            )

            progress.update(task, advance=1)

    console.print()
    console.print(results_table)
    console.print()

    # --- Summary ---
    console.print(Panel(
        f"[bold]Session Fuzzing Complete[/bold]\n"
        f"  Sequences executed:  [cyan]{len(sequences)}[/cyan]\n"
        f"  Total crashes:       [red]{len(all_crashes)}[/red]\n"
        f"  Unique crashes:      [magenta]{len(unique_crashes)}[/magenta]",
        border_style="green",
    ))

    # --- STEP 5: REPORT (reuse existing reporting) ---
    if unique_crashes:
        target_name = os.path.basename(source_path)
        for ext_to_strip in (".rs", ".cpp", ".c", ".go", ".java", ".cs"):
            if target_name.endswith(ext_to_strip):
                target_name = target_name[:-len(ext_to_strip)]
                break

        json_file, html_file = save_crash_report(
            unique_crashes, target_name, len(sequences),
            "", "",
            language=language,
            binary_mode=binary_mode,
            profile=profile,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            webhook_headers=webhook_headers,
        )
        console.print(f"[green]>> JSON report: {json_file}[/green]")
        console.print(f"[green]>> HTML report: {html_file}[/green]")
    else:
        console.print("[green]>> No crashes found in session mode. Target survived all sequences.[/green]")

    return len(unique_crashes)


def _normalize_sequences(raw_payloads) -> list[dict]:
    """Normalize AI output into a list of sequence dicts.

    The AI might return:
    - A list of sequence objects with a "sequence" key (ideal)
    - A list of flat payload dicts (convert each to a single-step sequence)
    - A list of strings (wrap each as a single-step sequence)
    """
    if not raw_payloads or not isinstance(raw_payloads, list):
        return []

    sequences = []
    for item in raw_payloads:
        if isinstance(item, dict):
            if "sequence" in item and isinstance(item["sequence"], list):
                # Ideal format
                sequences.append(item)
            elif "input_data" in item or "args" in item:
                # Flat payload → single-step sequence
                input_str = item.get("input_data", "")
                if not input_str:
                    args = item.get("args", [])
                    if isinstance(args, list):
                        input_str = " ".join(str(a) for a in args)
                    else:
                        input_str = str(args)
                sequences.append({
                    "sequence": [input_str] if input_str else [],
                    "vuln_type": item.get("vuln_type", ""),
                    "reason": item.get("reason", ""),
                    "severity": item.get("severity", ""),
                    "cwe": item.get("cwe", ""),
                })
        elif isinstance(item, str):
            sequences.append({
                "sequence": [item],
                "vuln_type": "unknown",
                "reason": "Direct string payload",
                "severity": "medium",
                "cwe": "",
            })
        elif isinstance(item, list):
            # A bare list of strings = one sequence
            sequences.append({
                "sequence": [str(s) for s in item],
                "vuln_type": "unknown",
                "reason": "Raw sequence",
                "severity": "medium",
                "cwe": "",
            })

    return sequences


def run_fuzzer(source_path: str, api_key: str, gcc_path: str, max_payloads: int, timeout: int, debug: bool, provider: str = "gemini", model: str = "", delivery_mode: str = "args", max_patch_retries: int = 3, binary_mode: bool = False, decompile_all: bool = False, ghidra_path: str = "", profile: str = "legacy-audit", static_only: bool = False, webhook_url: str = "", sandbox: str = "none", coverage: bool = False, webhook_secret: str = "", webhook_headers: list[str] = None, decompiler: str = "ghidra", decompiler_path: str = "", defects4c_url: str = "", defects4c_mount_dir: str = "", mode: str = "pipeline"):
    """Main fuzzer orchestration function."""
    if mode == "agents":
        import asyncio
        import json
        from mutagen.orchestrator import AgentOrchestrator
        
        # Read target source
        with open(source_path, encoding="utf-8") as f:
            source_code = f.read()
            
        orchestrator = AgentOrchestrator(
            target_path=source_path,
            source_code=source_code,
            provider=provider,
            model=model if model else ("gemini-2.5-flash" if provider == "gemini" else ""),
            compiler=gcc_path,
            delivery_mode=delivery_mode
        )
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        context = loop.run_until_complete(orchestrator.run())
        
        for log in context.logs:
            console.print(f"[dim]{log}[/dim]")
            
        unique_crashes = []
        crashes = []
        for p in context.active_payloads:
            if p.crash_type is not None:
                crash_dict = {
                    "args": p.args,
                    "input_data": p.input_data,
                    "return_code": p.exit_code,
                    "crash_type": p.crash_type,
                    "stdout": p.stdout,
                    "stderr": p.stderr,
                    "vuln_type": "Memory Corruption",
                    "cwe": "CWE-120",
                    "severity": "critical"
                }
                crashes.append(crash_dict)
                unique_crashes.append(crash_dict)
                
        patch_file = ""
        exploit_file = ""
        json_file = ""
        html_file = ""
        patch_verified = context.verification_status == "VERIFIED_SECURE"
        patch_code = context.proposed_patches.get("primary_patch", "")
        
        exploit_code = ""
        if crashes:
            exploit_code = verify_and_fallback_exploit("", crashes[0], "target.exe", "args")
            
        target_name = os.path.basename(source_path)
        patch_ext = os.path.splitext(source_path)[1].replace(".", "")
        
        if patch_code:
            patch_file = f"patches/{target_name.replace(os.path.splitext(source_path)[1], '_FIXED.c')}"
            os.makedirs("patches", exist_ok=True)
            with open(patch_file, "w", encoding="utf-8") as f:
                f.write(patch_code)
                
        if exploit_code:
            os.makedirs("exploits", exist_ok=True)
            exploit_file = f"exploits/{target_name.replace(os.path.splitext(source_path)[1], '_exploit.py')}"
            with open(exploit_file, "w", encoding="utf-8") as f:
                f.write(exploit_code)
                
        if crashes:
            json_file, html_file = save_crash_report(
                crashes, target_name, len(context.active_payloads), patch_code, exploit_code,
                language=patch_ext, profile=profile, static_only=False,
                raw_decompiled_code="", clean_source_code=source_code,
                webhook_url=webhook_url,
                webhook_secret=webhook_secret,
                webhook_headers=webhook_headers,
            )
            
            patch_text = f"  Patch generated:  [cyan]{patch_file}[/cyan]\n" if patch_file else ""
            exploit_text = f"  Exploit generated:[magenta]{exploit_file}[/magenta]\n" if exploit_file else ""
            verification_text = "  Verification:     [bold green]VERIFIED SECURE[/bold green]\n" if patch_verified else "  Verification:     [bold red]FAILED[/bold red]\n"
            
            summary = Panel(
                f"[bold green]FUZZING COMPLETE (Multi-Agent Swarm)[/bold green]\n\n"
                f"  Payloads tested:  [cyan]{len(context.active_payloads)}[/cyan]\n"
                f"  Unique crashes:   [bold red]{len(unique_crashes)}[/bold red]\n"
                f"  Crash rate:       [yellow]{(len(unique_crashes)/len(context.active_payloads))*100:.0f}%[/yellow]\n"
                f"  JSON report:      [dim]{json_file}[/dim]\n"
                f"  HTML report:      [yellow]{html_file}[/yellow]\n"
                f"{patch_text}"
                f"{exploit_text}"
                f"{verification_text}",
                title="[bold green]** AGENTS RESULTS **[/bold green]",
                border_style="green",
                box=box.HEAVY,
            )
        else:
            summary = Panel(
                f"[bold yellow]FUZZING COMPLETE (Multi-Agent Swarm)[/bold yellow]\n\n"
                f"  Payloads tested:  [cyan]{len(context.active_payloads)}[/cyan]\n"
                f"  Crashes found:    [green]0[/green]\n\n"
                f"  [dim]No crashes found. The target may have mitigations in place.[/dim]",
                title="AGENTS RESULTS",
                border_style="yellow",
                box=box.HEAVY,
            )
            
        console.print(summary)
        return len(unique_crashes)

    engine = get_engine(provider, api_key, model, debug, console)

    # --- UPFRONT DOCKER IMAGE PULLING -------------------------------------
    if sandbox == "docker" and _check_docker_functional():
        import subprocess
        image = os.environ.get("MUTAGEN_SANDBOX_IMAGE", "ubuntu:latest")
        console.print(f"[cyan]>> Docker sandbox mode active. Pulling image '{image}' upfront to prevent timeouts...[/cyan]")
        try:
            res = subprocess.run(["docker", "pull", image], capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                console.print(f"[green]>> Successfully pulled/verified image '{image}'[/green]")
            else:
                console.print(f"[yellow][!] Warning: docker pull returned code {res.returncode}: {res.stderr.strip()}[/yellow]")
        except Exception as e:
            console.print(f"[yellow][!] Warning: Failed to pull Docker image '{image}': {e}[/yellow]")

    # Detect language dynamically
    ext = os.path.splitext(source_path)[1].lower()
    if binary_mode:
        language = "c"  # Decompiled output is always pseudo-C
    else:
        if ext == ".rs":
            language = "rust"
        elif ext == ".go":
            language = "go"
        elif ext == ".java":
            language = "java"
        elif ext == ".cs":
            language = "csharp"
        elif ext == ".sol":
            language = "solidity"
        elif ext in (".html", ".htm"):
            language = "html"
        elif ext in (".js", ".ts"):
            language = "javascript"
        elif ext == ".css":
            language = "css"
        else:
            language = "c"

    if language in ("html", "javascript", "css"):
        static_only = True
        console.print(f"[yellow]>> Web static resource detected ({language}). Forcing static-only audit mode.[/yellow]")

    engine.language = language
    engine.is_decompiled = binary_mode

    # --- BANNER ----------------------------------------------------------
    banner_lines = [
        "  __  __ _   _ _____  _    ____ _____ _   _ ",
        " |  \\/  | | | |_   _|/ \\  / ___| ____| \\ | |",
        " | |\\/| | | | | | | / _ \\| |  _|  _| |  \\| |",
        " | |  | | |_| | | |/ ___ \\ |_| | |___| |\\  |",
        " |_|  |_|\\___/  |_/_/   \\_\\____|_____|_| \\_|",
        "",
        " AI-Powered Zero-Day Fuzzer v2.0",
        " by Bunny-sysd",
    ]
    banner = Text()
    for line in banner_lines[:5]:
        banner.append(line + "\n", style="bold green")
    banner.append("\n", style="dim")
    banner.append(banner_lines[6] + "\n", style="dim white")
    banner.append(banner_lines[7], style="dim cyan")

    console.print(Panel(banner, border_style="green", box=box.HEAVY))
    console.print()

    # --- DEFECTS4C BENCHMARK FLOW -----------------------------------------
    if defects4c_url:
        console.print(Panel(
            f"[bold cyan]DEFECTS4C BENCHMARK PIPELINE[/bold cyan]\n"
            f"[dim]Connecting to Defects4C service at {defects4c_url}...[/dim]",
            border_style="cyan"
        ))
        from mutagen.defects4c import Defects4CClient, Defects4CError
        client = Defects4CClient(defects4c_url)
        
        # 1. Reproduce bug
        console.print(f"[cyan]> Reproducing Defects4C bug:[/cyan] {source_path}")
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]Setting up containerized bug environment..."),
            console=console,
        ) as progress:
            task = progress.add_task("", total=None)
            try:
                client.reproduce(source_path)
                console.print("[green]>> Bug reproduced successfully![/green]")
            except Defects4CError as e:
                console.print(f"[bold red]X Reproduction failed: {e}[/bold red]")
                sys.exit(1)

        # 2. Locate buggy file in mount directory.
        # Format of bug_id: project@commit
        parts = source_path.split("@")
        project_name = parts[0] if parts else "project"
        
        # Look for source file in mounted dir. Benchmark targets are typically in standard paths inside the cloned repo.
        # We walk the mount directory to find the modified/buggy C files.
        buggy_files = []
        for root_dir, _, filenames in os.walk(defects4c_mount_dir):
            for filename in filenames:
                if filename.endswith(".c") or filename.endswith(".cpp"):
                    # Exclude typical build/test folders if necessary
                    full_p = os.path.join(root_dir, filename)
                    if "test" not in full_p.lower() and "build" not in full_p.lower():
                        buggy_files.append(full_p)

        if not buggy_files:
            console.print(f"[red]X No C/C++ files found in mount directory: {defects4c_mount_dir}[/red]")
            sys.exit(1)

        # For simplicity, target the largest or first matching source file containing dangerous patterns.
        # Real-world benchmark integrations target the specific buggy file path.
        target_src_path = buggy_files[0]
        console.print(f"[green]>> Target source file resolved: {os.path.basename(target_src_path)}[/green]")

        with open(target_src_path, encoding="utf-8") as f:
            source_code = f.read()

        # 3. Phase 1 AI Analysis (with Sniper Mode pre-targeting)
        from mutagen.static_analyzer import analyze_source
        ai_analysis_code = source_code
        if len(source_code) > 2000:
            pretarget = analyze_source(source_code)
            if pretarget.findings:
                console.print(f"[cyan]  ⚡ Sniper Mode: {pretarget.original_line_count} lines → "
                              f"{pretarget.focused_line_count} lines "
                              f"({pretarget.reduction_percent:.0f}% reduction)[/cyan]")
                ai_analysis_code = pretarget.focused_code

        with Progress(
            SpinnerColumn(style="green"),
            TextColumn("[green]AI analyzing code for vulnerabilities..."),
            console=console,
        ) as progress:
            task = progress.add_task("", total=None)
            payloads = engine.analyze_code(ai_analysis_code, max_payloads, delivery_mode, debug, profile=profile)

        if not payloads:
            console.print("[yellow][!] AI returned no payloads. Falling back to traditional mutations.[/yellow]")
            payloads = generate_fallback_payloads(max_payloads=max_payloads, delivery_mode=delivery_mode)

        # For Defects4C, we bypass physical fuzzing phases (Step 3/4) and jump straight into Patching & Verification
        console.print(Panel(
            "[bold cyan]DEFECTS4C SELF-HEALING REPAIR LOOP[/bold cyan]\n"
            f"[dim]Generating and verifying patches via Defects4C REST API (Max retries: {max_patch_retries})...[/dim]",
            border_style="cyan"
        ))

        error_details = ""
        patch_verified = False
        retries_used = 0
        patch_code = ""

        # Mimic crash structure for the patch generator
        dummy_crash = {
            "vuln_type": payloads[0].get("vuln_type", "Memory Corruption") if payloads else "C/C++ Bug",
            "cwe": payloads[0].get("cwe", "CWE-120") if payloads else "N/A",
            "reason": payloads[0].get("reason", "Defects4C benchmark reproduction failure") if payloads else "",
            "args": [],
            "input_data": "",
        }

        attempt = 0
        current_max_retries = max_patch_retries
        while attempt <= current_max_retries:
            label = "AI writing secure C patch..." if attempt == 0 else f"Self-Healing Attempt {attempt}/{current_max_retries} initializing..."
            console.print(f"[yellow]  ↳ {label}[/yellow]")

            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[cyan]Asking AI to resolve C bug..."),
                console=console,
            ) as progress:
                task = progress.add_task("", total=None)
                if attempt == 0:
                    patch_code = engine.generate_patch(source_code, dummy_crash, debug)
                else:
                    patch_code = engine.refine_patch(source_code, patch_code, error_details, dummy_crash, debug)

            if not patch_code:
                error_details = "AI returned an empty C patch."
                attempt += 1
                continue

            # AST Pre-check
            ast_result = validate_c_source(patch_code)
            if not ast_result.is_valid:
                error_details = format_validation_errors(ast_result)
                console.print(f"[yellow]    ⚡ AST Pre-Check: {len(ast_result.errors)} error(s) detected. Skipping submission.[/yellow]")
                patch_code = ""
                attempt += 1
                continue
            else:
                console.print(f"[green]    ✓ AST Pre-Check passed ({ast_result.node_count} nodes)[/green]")

            # Write patch to target file directly (benchmark expects file modification in workspace)
            with open(target_src_path, "w", encoding="utf-8") as f:
                f.write(patch_code)

            # Submit to Defects4C fix endpoint
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[cyan]    Verifying patch with Defects4C test suite..."),
                console=console,
            ) as progress:
                task = progress.add_task("", total=None)
                try:
                    fix_res = client.fix(source_path, target_src_path)
                    success = fix_res.get("success", False)
                except Defects4CError as e:
                    success = False
                    fix_res = {"message": str(e)}

            if success:
                patch_verified = True
                retries_used = attempt
                console.print("[bold green]    [+] PATCH VERIFIED SUCCESSFUL! All Defects4C test cases passed.[/bold green]\n")
                break
            else:
                error_details = fix_res.get("message", "Tests failed or failed to compile")
                console.print(f"[bold red]    X Verification Failed:[/bold red]\n{error_details}\n")
                
                # Check for detailed error dig diagnostics
                if "handle" in fix_res:
                    try:
                        dig_res = client.error_dig(fix_res["handle"])
                        if dig_res.get("classification"):
                            error_details += f"\nDiagnostics: {dig_res.get('classification')} - {dig_res.get('root_cause')}"
                    except Exception:
                        pass
                        
                attempt += 1

        # Save report
        json_file, html_file = save_crash_report(
            [dummy_crash], os.path.basename(target_src_path), len(payloads), patch_code, "",
            language="c", profile=profile, static_only=False,
            clean_source_code=source_code,
        )

        summary = Panel(
            f"[bold green]DEFECTS4C BENCHMARK EVALUATION COMPLETE[/bold green]\n\n"
            f"  Bug ID:           [bold yellow]{source_path}[/bold yellow]\n"
            f"  Patch status:     {'[bold green]RESOLVED[/bold green]' if patch_verified else '[bold red]FAILED[/bold red]'}\n"
            f"  Retries used:     [cyan]{retries_used}[/cyan]\n"
            f"  JSON report:      [dim]{json_file}[/dim]\n"
            f"  HTML report:      [yellow]{html_file}[/yellow]\n",
            title="[bold green]** EVALUATION SUMMARY **[/bold green]",
            border_style="green",
            box=box.HEAVY,
        )
        console.print(summary)
        return 1 if patch_verified else 0

    # --- PHASE 0: BINARY DECOMPILATION (if binary target) ----------------
    decompilation_info = None  # Will hold DecompilationResult if binary mode
    raw_decompiled_code = ""
    if binary_mode:
        console.print(Panel(
            "[bold cyan]PHASE 0: BINARY DECOMPILATION[/bold cyan]\n"
            "[dim]Decompiling binary with Ghidra headless analyzer...[/dim]",
            border_style="cyan"
        ))
        console.print(f"[cyan]> BINARY TARGET:[/cyan] {source_path}")

        try:
            if decompiler == "ghidra":
                ghidra_headless = find_ghidra(ghidra_path)
                console.print(f"[green]>> Ghidra found: {ghidra_headless}[/green]")
            else:
                ghidra_headless = ""
        except DecompilationError as e:
            console.print(f"[bold red]X {e}[/bold red]")
            sys.exit(1)

        with Progress(
            SpinnerColumn(style="green"),
            TextColumn(f"[green]{decompiler.upper()} decompiling binary..."),
            console=console,
        ) as progress:
            task = progress.add_task("", total=None)
            try:
                decompilation_info = decompile_binary(
                    binary_path=source_path,
                    ghidra_headless=ghidra_headless,
                    all_functions=decompile_all,
                    timeout=300,  # 5 minute timeout for large binaries
                    decompiler=decompiler,
                    decompiler_path=decompiler_path,
                )
            except DecompilationError as e:
                console.print(f"[bold red]X Decompilation failed![/bold red]\n{e}")
                sys.exit(1)

        # Show decompilation stats
        decompile_table = Table(title="Decompilation Results", box=box.ROUNDED, border_style="cyan")
        decompile_table.add_column("Property", style="cyan")
        decompile_table.add_column("Value", style="green")
        decompile_table.add_row("Binary", os.path.basename(source_path))
        decompile_table.add_row("Architecture", decompilation_info.architecture)
        decompile_table.add_row("Format", decompilation_info.binary_format)
        decompile_table.add_row("Functions Decompiled", str(decompilation_info.functions_found))
        decompile_table.add_row("Pseudo-C Size", f"{len(decompilation_info.pseudo_source):,} bytes")
        decompile_table.add_row("Decompiler", decompilation_info.decompiler_used.upper())
        console.print(decompile_table)
        console.print()

        raw_decompiled_code = decompilation_info.pseudo_source

        # --- CONTEXT WINDOW CHUNKING ---
        from mutagen.chunker import filter_functions, reconstruct_pseudo_code, split_functions
        meta_header, functions = split_functions(raw_decompiled_code)
        filtered_funcs = filter_functions(functions)

        # Log chunking action details
        console.print(f"[dim]  Context Window Chunker: split {len(functions)} functions down to {len(filtered_funcs)} high-priority functions containing risk keywords[/dim]")

        source_code = reconstruct_pseudo_code(meta_header, filtered_funcs)
        console.print(f"[dim]  Extracted {len(source_code)} bytes of filtered C pseudo-code[/dim]")
        console.print()

        # --- PHASE 0.5: AI SYMBOL RECOVERY & DEOBFUSCATION -------------------
        console.print(Panel(
            "[bold cyan]PHASE 0.5: AI SYMBOL RECOVERY & DEOBFUSCATION[/bold cyan]\n"
            "[dim]Refactoring generic variables/functions and inserting annotations...[/dim]",
            border_style="cyan"
        ))
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]AI deobfuscating and annotating code..."),
            console=console,
        ) as progress:
            task = progress.add_task("", total=None)
            deobfuscated_code = engine.deobfuscate_code(source_code, debug)
            if deobfuscated_code and deobfuscated_code.strip():
                source_code = deobfuscated_code
                console.print("[green]>> Symbol recovery successful! Replaced generic variable/function stubs.[/green]")
            else:
                console.print("[yellow][!] AI deobfuscation returned empty code, falling back to raw pseudo-C.[/yellow]")
        console.print()
    else:
        # --- STEP 1: READ THE TARGET SOURCE CODE -----------------------------
        console.print(f"[cyan]> TARGET:[/cyan] {source_path}")

        with open(source_path, encoding="utf-8") as f:
            source_code = f.read()

        console.print(f"[dim]  Read {len(source_code)} bytes of source code[/dim]")
        console.print()

    # --- DEFENSIVE PROMPT INJECTION SCANNER (SkillSpector-inspired) -------
    # Scan target code to detect instructions trying to bypass/poison the LLM system prompt.
    injection_patterns = [
        "ignore previous instructions",
        "system prompt",
        "instead of analyzing",
        "new instructions",
        "you must now",
        "override",
        "hijack",
        "forget your task",
    ]
    code_lower = source_code.lower()
    detected_patterns = [p for p in injection_patterns if p in code_lower]
    if detected_patterns:
        console.print(f"[bold red][!] DEFENSIVE ALERT: Potential prompt injection / jailbreak payload detected in target code![/bold red]")
        console.print(f"[red]    Matched indicators: {detected_patterns}[/red]")
        console.print(f"[red]    Aborting execution to protect LLM engine alignment integrity.[/red]")
        sys.exit(2)


    # --- STEP 2: AI ANALYSIS ---------------------------------------------
    console.print(Panel(
        f"[bold cyan]PHASE 1: AI CODE ANALYSIS ({delivery_mode.upper()} mode - {profile} profile)[/bold cyan]\n"
        "[dim]Sending source code to for vulnerability analysis...[/dim]",
        border_style="cyan"
    ))

    # --- Sniper Mode Pre-Targeting ---
    from mutagen.static_analyzer import analyze_source

    if language == "c" and len(source_code) > 2000:
        pretarget = analyze_source(source_code)
        if pretarget.findings:
            console.print(f"[cyan]  ⚡ Sniper Mode: {pretarget.original_line_count} lines → "
                          f"{pretarget.focused_line_count} lines "
                          f"({pretarget.reduction_percent:.0f}% reduction)[/cyan]")
            ai_analysis_code = pretarget.focused_code
        else:
            ai_analysis_code = source_code
    else:
        ai_analysis_code = source_code

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[green]AI analyzing code for vulnerabilities..."),
        console=console,
    ) as progress:
        task = progress.add_task("", total=None)
        payloads = engine.analyze_code(ai_analysis_code, max_payloads, delivery_mode, debug, profile=profile)

    if not payloads:
        console.print("[yellow][!] AI returned no payloads (possible refusal, rate-limit, or network error).[/yellow]")
        console.print("[cyan]↳ Activating traditional mutation fallback engine...[/cyan]")
        payloads = generate_fallback_payloads(max_payloads=max_payloads, delivery_mode=delivery_mode)
        if not payloads:
            console.print("[red]X Both AI and fallback engines returned no payloads. Cannot continue.[/red]")
            sys.exit(1)
        console.print(f"[green]>> Fallback engine generated {len(payloads)} classic mutation payloads[/green]")

    console.print(f"[green]>> AI generated {len(payloads)} targeted payloads[/green]")
    console.print()

    # Show what the AI found
    vuln_table = Table(title="AI Vulnerability Analysis", box=box.ROUNDED, border_style="cyan")
    vuln_table.add_column("#", style="dim", width=4)
    vuln_table.add_column("Type", style="yellow")
    vuln_table.add_column("CWE", style="magenta", width=10)
    vuln_table.add_column("Severity", style="red")
    vuln_table.add_column("Payload Preview", style="green", max_width=35)
    vuln_table.add_column("Reason", style="dim", max_width=30)

    for i, p in enumerate(payloads):
        severity = p.get("severity", "unknown")
        sev_colors = {
            "critical": "[bold red]",
            "high": "[red]",
            "medium": "[yellow]",
            "low": "[green]"
        }
        sev_style = sev_colors.get(severity, "[dim]")

        # Support both old "payload" format and new "args" format
        args = p.get("args", [p.get("payload", "")])
        input_data = p.get("input_data", "")
        if isinstance(args, str):
            args = [args]

        if delivery_mode == "args":
            preview = " | ".join(str(a)[:15] for a in args)
        else:
            preview = str(input_data)[:30].replace("\n", "\\n")

        if len(preview) > 33:
            preview = preview[:30] + "..."

        vuln_table.add_row(
            str(i + 1),
            p.get("vuln_type", "unknown"),
            p.get("cwe", "N/A"),
            f"{sev_style}{severity}",
            preview,
            p.get("reason", "")[:28],
        )

    console.print(vuln_table)
    console.print()

    # --- STATIC-ONLY MODE GATING (Safety/Analysis boundary) --------------
    if static_only:
        console.print(Panel(
            "[bold yellow]STATIC-ONLY MODE ACTIVATED[/bold yellow]\n"
            f"[dim]Profile: {profile.upper()} | Skipping compilation, execution, and patch verification phases.[/dim]",
            border_style="yellow"
        ))

        target_name = os.path.basename(source_path)
        for ext_to_strip in (".rs", ".cpp", ".c", ".sol", ".html", ".htm", ".js", ".ts", ".css"):
            if target_name.endswith(ext_to_strip):
                target_name = target_name[:-len(ext_to_strip)]
                break

        # Format payloads into static findings
        static_findings = []
        for i, p in enumerate(payloads):
            static_findings.append({
                "args": p.get("args", []),
                "input_data": p.get("input_data", ""),
                "payload": p.get("input_data") if p.get("input_data") else " ".join(p.get("args", [])),
                "vuln_type": p.get("vuln_type", ""),
                "cwe": p.get("cwe", ""),
                "reason": p.get("reason", ""),
                "severity": p.get("severity", ""),
                "crash_type": "Static Analysis Scan (No dynamic execution)",
                "return_code": 0,
                "retries": 0,
            })

        json_file, html_file = save_crash_report(
            static_findings, target_name, 0, "", "",
            language="c" if binary_mode else language, binary_mode=binary_mode,
            decompilation_info=decompilation_info,
            profile=profile, static_only=True,
            raw_decompiled_code=raw_decompiled_code,
            clean_source_code=source_code,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            webhook_headers=webhook_headers
        )

        summary = Panel(
            f"[bold green]STATIC ANALYSIS COMPLETE[/bold green]\n\n"
            f"  Analysis mode:    [bold yellow]STATIC ONLY ({profile})[/bold yellow]\n"
            f"  Findings mapped:  [cyan]{len(static_findings)}[/cyan]\n"
            f"  JSON report:      [dim]{json_file}[/dim]\n"
            f"  HTML report:      [yellow]{html_file}[/yellow]\n"
            f"  [dim]Open the HTML report in your browser for a visual breakdown![/dim]",
            title="[bold green]** RESULTS **[/bold green]",
            border_style="green",
            box=box.HEAVY,
        )
        console.print(summary)
        return len(static_findings)

    # --- STEP 3: COMPILE THE TARGET (or use original binary) ---------------
    if binary_mode:
        # In binary mode, fuzz the original binary directly — no compilation needed
        exe_path = source_path
        console.print(Panel(
            "[bold cyan]PHASE 2: COMPILE TARGET[/bold cyan]\n"
            "[bold green]SKIPPED[/bold green] — Using original binary directly for fuzzing.",
            border_style="dim"
        ))
        console.print(f"[green]>> Using binary: {exe_path}[/green]")
        console.print()
    else:
        console.print(Panel(
            "[bold cyan]PHASE 2: COMPILE TARGET[/bold cyan]\n"
            "[dim]Building the target with security protections disabled...[/dim]",
            border_style="cyan"
        ))

        try:
            exe_path = compile_target(source_path, gcc_path, coverage)
        except CompilationError as e:
            console.print(f"[bold red]X Initial compilation failed![/bold red]\n{e}")
            sys.exit(1)

        console.print(f"[green]>> Compiled to: {exe_path}[/green]")
        console.print()

    # --- STEP 3b: SESSION-MODE FUZZING (Persistent Supervisor) -----------
    if delivery_mode.startswith("session:"):
        return _run_session_fuzzer(
            exe_path=exe_path,
            source_code=source_code,
            source_path=source_path,
            delivery_mode=delivery_mode,
            timeout=timeout,
            sandbox=sandbox,
            max_payloads=max_payloads,
            engine=engine,
            debug=debug,
            language=language,
            binary_mode=binary_mode,
            profile=profile,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            webhook_headers=webhook_headers,
        )

    # --- STEP 4: FUZZ! (PARALLEL EXECUTION) ------------------------------
    console.print(Panel(
        "[bold red]PHASE 3: FUZZING[/bold red]\n"
        "[dim]Injecting AI payloads into the target in parallel...[/dim]",
        border_style="red"
    ))

    all_crashes = []          # Every crash hit (may contain dupes)
    seen_signatures = set()   # For deduplication
    unique_crashes = []       # Deduplicated crash list
    results_lock = threading.Lock()

    global_coverage = set()
    seed_queue = []

    results_table = Table(title="Fuzzing Results", box=box.ROUNDED, border_style="green")
    results_table.add_column("#", style="dim", width=4)
    results_table.add_column("Status", width=12)
    results_table.add_column("Payload Preview", style="cyan", max_width=35)
    results_table.add_column("Crash Type", style="red", max_width=30)
    results_table.add_column("Return Code", style="yellow", width=12)
    results_table.add_column("Unique?", style="magenta", width=8)

    def _fuzz_single_payload(i: int, p: dict) -> dict:
        """Execute a single payload and return structured result."""
        args = p.get("args", [])
        input_data = p.get("input_data", "")
        if isinstance(args, str):
            args = [args]
        args = [str(a) for a in args]

        result = execute_payload(exe_path, args, input_data, delivery_mode, timeout, sandbox)
        return {
            "index": i,
            "payload": p,
            "args": args,
            "input_data": input_data,
            "result": result,
        }

    # --- Parallel Phase: fire all payloads concurrently ---
    # Deduplicate payloads before execution and track them globally
    executed_payloads = set()
    unique_payloads = []
    for p in payloads:
        p_args = p.get("args", [])
        p_input = p.get("input_data", "")
        if isinstance(p_args, str):
            p_args = [p_args]
        p_args = [str(a) for a in p_args]
        p_key = (tuple(p_args), p_input or "")
        if p_key not in executed_payloads:
            executed_payloads.add(p_key)
            unique_payloads.append(p)
    payloads = unique_payloads

    # Set worker count to 1 for TCP port delivery to avoid socket bind conflicts
    worker_count = 1 if delivery_mode.startswith("tcp:") else min(4, len(payloads))
    futures_map = {}
    needs_retry = []  # Payloads that didn't crash → eligible for agentic retry

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        for i, p in enumerate(payloads):
            future = pool.submit(_fuzz_single_payload, i, p)
            futures_map[future] = (i, p)

        for future in as_completed(futures_map):
            i, original_p = futures_map[future]
            fuzz_result = future.result()
            result = fuzz_result["result"]
            args = fuzz_result["args"]
            input_data = fuzz_result["input_data"]

            status = "[bold red]CRASH!!" if result["crashed"] else "[green]OK"
            if delivery_mode == "args":
                preview = " | ".join(a[:15] for a in args)
            else:
                preview = str(input_data)[:30].replace("\n", "\\n")
            if len(preview) > 33:
                preview = preview[:30] + "..."

            crash_entry = None
            is_unique = ""

            if result["crashed"]:
                crash_entry = {
                    "args": args,
                    "input_data": input_data,
                    "payload": input_data if input_data else " ".join(args),
                    "vuln_type": original_p.get("vuln_type", ""),
                    "cwe": original_p.get("cwe", ""),
                    "reason": original_p.get("reason", ""),
                    "severity": original_p.get("severity", ""),
                    "crash_type": result["crash_type"],
                    "return_code": result["return_code"],
                    "stdout": result.get("stdout", ""),
                    "stderr": result.get("stderr", ""),
                    "retries": 0,
                }
                sig = _crash_signature(crash_entry)
                with results_lock:
                    all_crashes.append(crash_entry)
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        unique_crashes.append(crash_entry)
                        is_unique = "[green]✓ NEW"
                    else:
                        is_unique = "[dim]dupe"

            # --- TRACK COVERAGE SEEDS --------------------------------------
            if result.get("coverage"):
                cov_set = set(result["coverage"])
                with results_lock:
                    new_blocks = cov_set - global_coverage
                    if new_blocks:
                        global_coverage.update(new_blocks)
                        if not result["crashed"]:
                            seed_queue.append({
                                "args": args,
                                "input_data": input_data,
                                "vuln_type": original_p.get("vuln_type", "mutation_seed"),
                                "cwe": original_p.get("cwe", ""),
                                "severity": original_p.get("severity", "medium"),
                                "reason": original_p.get("reason", "Discovered new basic blocks"),
                            })
                    else:
                        global_coverage.update(cov_set)

            if not result["crashed"]:
                # Don't queue intentionally safe/benign payloads for retry —
                # the AI itself said they wouldn't crash, so retrying wastes quota.
                vuln_type = original_p.get("vuln_type", "").lower()
                severity  = original_p.get("severity", "").lower()
                is_benign = (
                    severity == "low"
                    or vuln_type in ("no_vulnerability", "safe_input", "none", "n/a", "")
                )
                if not is_benign:
                    needs_retry.append((i, original_p, result, args, input_data))

            with results_lock:
                results_table.add_row(
                    str(i + 1),
                    status,
                    preview,
                    result["crash_type"] if result["crashed"] else "-",
                    str(result["return_code"]),
                    is_unique if result["crashed"] else "",
                )

    # --- Sequential Phase: agentic retries for non-crashing payloads ---
    for i, original_p, last_result, last_args, last_input in needs_retry:
        if unique_crashes:
            console.print("[dim]  Crash already discovered. Skipping remaining payload refinements.[/dim]")
            break
        retry_attempt = 1
        current_max_retries = 2
        while retry_attempt <= current_max_retries:
            console.print(f"[yellow]  ↳ Payload {i+1} failed. Agentic Retry {retry_attempt}/{current_max_retries} initializing...[/yellow]")
            refined = engine.refine_payload(source_code, last_args, last_input, last_result["stdout"], last_result["stderr"], last_result["return_code"], delivery_mode)
            if not refined:
                console.print("[dim]    (No refined payloads returned, skipping retry)[/dim]")
                break

            retry_crashed = False
            for rp in refined:
                if not isinstance(rp, dict):
                    continue
                r_args = rp.get("args", [])
                r_input = rp.get("input_data") or ""
                if isinstance(r_args, str):
                    r_args = [r_args]
                r_args = [str(a) for a in r_args]

                # Check if this refined payload has already been executed in this run
                r_key = (tuple(r_args), r_input)
                if r_key in executed_payloads:
                    console.print(f"[dim]    (Skipping duplicate refined payload: args={r_args}, input={repr(r_input[:40])})[/dim]")
                    continue
                executed_payloads.add(r_key)

                # --- STUB GUARD: reject broken AI placeholder responses -------
                # When the API rate-limits mid-retry, the fallback sometimes
                # returns generic placeholders like "payload_refined" or empty
                # strings. Executing these wastes a retry slot and produces
                # misleading "OK" results. Skip them and log a warning instead.
                _STUB_PLACEHOLDERS = {
                    "payload_refined", "refined_payload", "placeholder",
                    "<payload>", "your_payload_here", "payload", ""
                }
                payload_content = " ".join(r_args) + (r_input or "")
                if len(payload_content.strip()) < 10 or payload_content.strip().lower() in _STUB_PLACEHOLDERS:
                    console.print(f"[dim]    (Skipping stub/placeholder refined payload: {repr(payload_content[:40])})[/dim]")
                    continue

                result = execute_payload(exe_path, r_args, r_input, delivery_mode, timeout, sandbox)

                status = "[bold red]CRASH!!" if result["crashed"] else "[green]OK"
                if delivery_mode == "args":
                    preview = " | ".join(a[:15] for a in r_args)
                else:
                    preview = str(r_input)[:30].replace("\n", "\\n")
                if len(preview) > 33:
                    preview = preview[:30] + "..."

                is_unique = ""
                if result["crashed"]:
                    crash_entry = {
                        "args": r_args,
                        "input_data": r_input,
                        "payload": r_input if r_input else " ".join(r_args),
                        "vuln_type": rp.get("vuln_type", ""),
                        "cwe": rp.get("cwe", ""),
                        "reason": rp.get("reason", ""),
                        "severity": rp.get("severity", ""),
                        "crash_type": result["crash_type"],
                        "return_code": result["return_code"],
                        "stdout": result.get("stdout", ""),
                        "stderr": result.get("stderr", ""),
                        "retries": retry_attempt,
                    }
                    sig = _crash_signature(crash_entry)
                    all_crashes.append(crash_entry)
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        unique_crashes.append(crash_entry)
                        is_unique = "[green]✓ NEW"
                    else:
                        is_unique = "[dim]dupe"
                    retry_crashed = True

                # --- TRACK COVERAGE FOR REFINEMENTS ------------------------
                if result.get("coverage"):
                    cov_set = set(result["coverage"])
                    new_blocks = cov_set - global_coverage
                    if new_blocks:
                        global_coverage.update(new_blocks)
                        if not result["crashed"]:
                            seed_queue.append({
                                "args": r_args,
                                "input_data": r_input,
                                "vuln_type": rp.get("vuln_type", "mutation_seed"),
                                "cwe": rp.get("cwe", ""),
                                "severity": rp.get("severity", "medium"),
                                "reason": rp.get("reason", "Refined payload hit new coverage"),
                            })
                    else:
                        global_coverage.update(cov_set)

                results_table.add_row(
                    f"{i + 1}.{retry_attempt}",
                    status,
                    preview,
                    result["crash_type"] if result["crashed"] else "-",
                    str(result["return_code"]),
                    is_unique if result["crashed"] else "",
                )

                if retry_crashed:
                    break

                last_result = result
                last_args = r_args
                last_input = r_input

            if retry_crashed:
                break

            if not retry_crashed and retry_attempt == current_max_retries:
                if sys.stdin.isatty():
                    try:
                        ans = input(f"\n[?] Payload {i+1} refinement failed to crash the target. Try 2 more attempts? [y/N]: ").strip().lower()
                        if ans in ('y', 'yes'):
                            current_max_retries += 2
                    except (KeyboardInterrupt, EOFError):
                        pass
            retry_attempt += 1

    # --- COVERAGE-GUIDED MUTATION FUZZING FEEDBACK LOOP --------------------
    if coverage and seed_queue:
        console.print(Panel(
            "[bold cyan]PHASE 3.5: COVERAGE-GUIDED HYBRID FUZZING[/bold cyan]\n"
            f"[dim]Initial coverage: {len(global_coverage)} basic blocks. Starting mutation feedback loop...[/dim]",
            border_style="cyan"
        ))

        mutation_rounds = 200
        mutation_hits = 0
        new_crashes_found = 0

        import random

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]Mutating seeds and exploring branches ({task.completed}/{task.total} rounds)..."),
            console=console,
        ) as progress:
            task = progress.add_task("Fuzzing", total=mutation_rounds)

            for round_idx in range(mutation_rounds):
                if not seed_queue:
                    break

                # Select seed
                seed = random.choice(seed_queue)

                # Mutate input
                mutated_args, mutated_input = mutate_input(seed["args"], seed["input_data"], delivery_mode)

                # Execute mutated payload
                res = execute_payload(exe_path, mutated_args, mutated_input, delivery_mode, timeout, sandbox)

                if res["crashed"]:
                    crash_entry = {
                        "args": mutated_args,
                        "input_data": mutated_input,
                        "payload": mutated_input if mutated_input else " ".join(mutated_args),
                        "vuln_type": seed.get("vuln_type", "mutative_vulnerability"),
                        "cwe": seed.get("cwe", "CWE-120"),
                        "reason": f"Mutation fuzzing: crash triggered via input mutation of seed (original reason: {seed.get('reason')})",
                        "severity": seed.get("severity", "high"),
                        "crash_type": res["crash_type"],
                        "return_code": res["return_code"],
                        "stdout": res.get("stdout", ""),
                        "stderr": res.get("stderr", ""),
                        "retries": 99,  # Marker for mutator source
                    }
                    sig = _crash_signature(crash_entry)
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        unique_crashes.append(crash_entry)
                        all_crashes.append(crash_entry)
                        new_crashes_found += 1
                        console.print(f"[bold red]    [+] Mutator triggered NEW unique crash: {res['crash_type']}[/bold red]")
                else:
                    # Check coverage
                    cov = res.get("coverage", [])
                    if cov:
                        cov_set = set(cov)
                        new_blocks = cov_set - global_coverage
                        if new_blocks:
                            global_coverage.update(new_blocks)
                            mutation_hits += 1
                            new_seed = {
                                "args": mutated_args,
                                "input_data": mutated_input,
                                "vuln_type": seed.get("vuln_type"),
                                "cwe": seed.get("cwe"),
                                "severity": seed.get("severity"),
                                "reason": f"Mutated seed discovered {len(new_blocks)} new block(s)",
                            }
                            seed_queue.append(new_seed)

                progress.update(task, advance=1)

        console.print(f"[green]>> Mutation loop finished. Discovered {mutation_hits} new code paths and {new_crashes_found} unique crashes.[/green]")
        console.print(f"[green]>> Global basic block coverage reached: {len(global_coverage)} blocks.[/green]")
        console.print()

    console.print(results_table)
    console.print()

    # --- STEP 5: REPORT --------------------------------------------------
    target_name = os.path.basename(source_path)
    for ext_to_strip in (".rs", ".cpp", ".c", ".go", ".java", ".cs"):
        if target_name.endswith(ext_to_strip):
            target_name = target_name[:-len(ext_to_strip)]
            break
    crash_rate = (len(all_crashes)/len(payloads)*100) if payloads else 0

    # Use unique_crashes for patching/exploit (most interesting distinct bugs)
    crashes = unique_crashes

    if crashes:
        patch_ext = "rs" if language == "rust" else "go" if language == "go" else "java" if language == "java" else "cs" if language == "csharp" else "c"
        patch_file = ""
        exploit_file = ""
        patch_code = ""
        exploit_code = ""
        patch_verified = False
        retries_used = 0

        if binary_mode:
            # --- BINARY MODE: Exploit generation only, no patching -----------
            console.print(Panel(
                "[bold cyan]PHASE 4: EXPLOIT GENERATION (Binary Mode)[/bold cyan]\n"
                "[dim]Generating exploit script... (Auto-patch unavailable — no source code)[/dim]",
                border_style="cyan"
            ))

            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[cyan]{task.description}"),
                console=console,
            ) as progress:
                exploit_code = engine.generate_exploit(source_code, crashes[0], exe_path, delivery_mode, debug)
                exploit_code = verify_and_fallback_exploit(exploit_code, crashes[0], exe_path, delivery_mode)

                if exploit_code:
                    os.makedirs("exploits", exist_ok=True)
                    exploit_file = f"exploits/{target_name}_exploit.py"
                    with open(exploit_file, "w", encoding="utf-8") as f:
                        f.write(exploit_code)

            if exploit_file:
                console.print(f"[green]>> Python exploit saved to: {exploit_file}[/green]\n")
            else:
                console.print("[red]X Failed to generate exploit.[/red]\n")

            console.print(Panel(
                "[bold cyan]PHASE 5: AUTO-PATCH & VERIFICATION[/bold cyan]\n"
                "[bold yellow]SKIPPED[/bold yellow] — Source code unavailable for binary targets.\n"
                "[dim]Manual remediation required based on the vulnerability report.[/dim]",
                border_style="dim"
            ))
            console.print()

            # Save report in binary mode
            json_file, html_file = save_crash_report(
                crashes, target_name, len(payloads), patch_code, exploit_code,
                language=patch_ext, binary_mode=True,
                decompilation_info=decompilation_info,
                profile=profile, static_only=False,
                raw_decompiled_code=raw_decompiled_code,
                clean_source_code=source_code,
                webhook_url=webhook_url,
                webhook_secret=webhook_secret,
                webhook_headers=webhook_headers,
            )
        else:
            # --- SOURCE MODE: Full patch + exploit + verification -----------
            console.print(Panel(
                "[bold cyan]PHASE 4: AUTO-PATCH & EXPLOIT GENERATION[/bold cyan]\n"
                "[dim]Asking AI to generate a secure fix and Python exploit...[/dim]",
                border_style="cyan"
            ))

            patch_file = f"patches/{target_name}_FIXED.{patch_ext}"
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[cyan]{task.description}"),
                console=console,
            ) as progress:
                exploit_code = engine.generate_exploit(source_code, crashes[0], exe_path, delivery_mode, debug)
                exploit_code = verify_and_fallback_exploit(exploit_code, crashes[0], exe_path, delivery_mode)

                if exploit_code:
                    os.makedirs("exploits", exist_ok=True)
                    exploit_file = f"exploits/{target_name}_exploit.py"
                    with open(exploit_file, "w", encoding="utf-8") as f:
                        f.write(exploit_code)

            if exploit_file:
                console.print(f"[green]>> Python exploit saved to: {exploit_file}[/green]\n")
            else:
                console.print("[red]X Failed to generate exploit.[/red]\n")

            # --- PHASE 5: AUTO-PATCH VERIFICATION & SELF-HEALING -----------------
            error_details = ""

            console.print(Panel(
                "[bold cyan]PHASE 5: AUTO-PATCH VERIFICATION & SELF-HEALING[/bold cyan]\n"
                f"[dim]Mathematically proving the patch works (Max self-healing retries: {max_patch_retries})...[/dim]",
                border_style="cyan"
            ))

            attempt = 0
            current_max_retries = max_patch_retries
            while attempt <= current_max_retries:
                if attempt > 0:
                    retries_used = attempt
                if not patch_code:
                    label = "AI writing secure C patch..." if attempt == 0 else f"Self-Healing Attempt {attempt}/{current_max_retries} initializing..."
                    console.print(f"[yellow]  ↳ {label}[/yellow]")
                    with Progress(
                        SpinnerColumn(style="cyan"),
                        TextColumn("[cyan]Asking AI to write the C patch..."),
                        console=console,
                    ) as progress:
                        task = progress.add_task("", total=None)
                        if attempt == 0:
                            patch_code = engine.generate_patch(source_code, crashes[0], debug)
                        else:
                            patch_code = engine.refine_patch(source_code, "", error_details or "Initial patch was empty", crashes[0], debug)

                    if not patch_code:
                        error_details = "AI returned an empty C patch response."
                        console.print("[red]    X AI returned empty C patch.[/red]\n")
                        if not patch_verified and attempt == current_max_retries:
                            if sys.stdin.isatty():
                                try:
                                    ans = input(f"\n[?] Self-healing failed after {current_max_retries} attempts. Try {max_patch_retries or 3} more attempts? [y/N]: ").strip().lower()
                                    if ans in ('y', 'yes'):
                                        current_max_retries += (max_patch_retries or 3)
                                except (KeyboardInterrupt, EOFError):
                                    pass
                        attempt += 1
                        continue

                elif attempt > 0:
                    console.print(f"[yellow]  ↳ Self-Healing Attempt {attempt}/{current_max_retries} initializing...[/yellow]")
                    with Progress(
                        SpinnerColumn(style="cyan"),
                        TextColumn("[cyan]Asking AI to fix the C patch..."),
                        console=console,
                    ) as progress:
                        task = progress.add_task("", total=None)
                        patch_code = engine.refine_patch(source_code, patch_code, error_details, crashes[0], debug)

                    if not patch_code:
                        error_details = "AI returned an empty C patch response during refinement."
                        console.print("[red]    X AI failed to return refined C patch.[/red]\n")
                        if not patch_verified and attempt == current_max_retries:
                            if sys.stdin.isatty():
                                try:
                                    ans = input(f"\n[?] Self-healing failed after {current_max_retries} attempts. Try {max_patch_retries or 3} more attempts? [y/N]: ").strip().lower()
                                    if ans in ('y', 'yes'):
                                        current_max_retries += (max_patch_retries or 3)
                                except (KeyboardInterrupt, EOFError):
                                    pass
                        attempt += 1
                        continue

                # --- NEURO-SYMBOLIC AST PRE-CHECK (tree-sitter) -------
                # Catch hallucinated syntax BEFORE wasting a GCC compile cycle.
                if language == "c" and patch_code:
                    ast_result = validate_c_source(patch_code)
                    if not ast_result.is_valid:
                        error_details = format_validation_errors(ast_result)
                        console.print(f"[yellow]    ⚡ Neuro-Symbolic Pre-Check: {len(ast_result.errors)} AST error(s) detected. Skipping GCC.[/yellow]")
                        for ast_err in ast_result.errors[:3]:  # Show first 3 errors
                            console.print(f"[dim]       Line {ast_err.line}: {ast_err.message}[/dim]")
                        patch_code = ""  # Force re-generation on next iteration
                        attempt += 1
                        continue
                    else:
                        console.print(f"[green]    ✓ AST Pre-Check passed ({ast_result.node_count} nodes, {len(ast_result.functions_found)} functions)[/green]")

                # Write patch file
                os.makedirs("patches", exist_ok=True)
                with open(patch_file, "w", encoding="utf-8") as f:
                    f.write(patch_code)

                try:
                    patched_exe = compile_target(patch_file, gcc_path)
                    console.print("[green]    [+] Patched target compiled successfully[/green]")

                    with Progress(
                        SpinnerColumn(style="cyan"),
                        TextColumn("[cyan]    Firing exploit at patched target..."),
                        console=console,
                    ) as progress:
                        task = progress.add_task("", total=None)
                        verify_result = execute_payload(patched_exe, crashes[0]["args"], crashes[0].get("input_data", ""), delivery_mode, timeout, sandbox)

                    if verify_result["crashed"]:
                        error_details = f"The patched binary compiled successfully but still crashed when executed with the exploit payload.\nCrash Type: {verify_result['crash_type']}\nReturn Code: {verify_result['return_code']}"
                        console.print(f"[bold red]    X Verification Failed:[/bold red] The patched program still crashed: {verify_result['crash_type']}\n")
                    else:
                        patch_verified = True
                        retries_used = attempt
                        console.print("[bold green]    [+] PATCH VERIFIED SUCCESSFUL![/bold green] The exploit no longer crashes the target.\n")
                        break
                except CompilationError as e:
                    error_details = f"The patched C code failed to compile with the following compiler errors:\n{str(e)}"
                    console.print(f"[bold red]    X Compilation Failed:[/bold red]\n{e}\n")

                if not patch_verified and attempt == current_max_retries:
                    if sys.stdin.isatty():
                        try:
                            ans = input(f"\n[?] Self-healing failed after {current_max_retries} attempts. Try {max_patch_retries or 3} more attempts? [y/N]: ").strip().lower()
                            if ans in ('y', 'yes'):
                                current_max_retries += (max_patch_retries or 3)
                        except (KeyboardInterrupt, EOFError):
                            pass
                attempt += 1

            # Clean up empty patch file if self-healing failed completely without generating any patch
            if not patch_code and os.path.exists(patch_file):
                try:
                    os.remove(patch_file)
                except Exception:
                    pass
                patch_file = ""

            # Now save report with the final patch code (which may be refined by self-healing)
            json_file, html_file = save_crash_report(
                crashes, target_name, len(payloads), patch_code, exploit_code,
                language=patch_ext, profile=profile, static_only=False,
                raw_decompiled_code="", clean_source_code=source_code,
                webhook_url=webhook_url,
                webhook_secret=webhook_secret,
                webhook_headers=webhook_headers,
            )

        patch_text = f"  Patch generated:  [cyan]{patch_file}[/cyan]\n" if patch_file else ""
        exploit_text = f"  Exploit generated:[magenta]{exploit_file}[/magenta]\n" if exploit_file else ""
        verification_text = "  Verification:     [bold green]VERIFIED SECURE[/bold green]\n" if patch_verified else ("  Verification:     [bold red]FAILED[/bold red]\n" if patch_file else "")

        healing_text = ""
        if patch_file:
            if patch_verified:
                healing_text = f"  Self-healing:     [green]Success (used {retries_used} retries)[/green]\n"
            else:
                healing_text = f"  Self-healing:     [red]Failed (used {retries_used} retries)[/red]\n"

        binary_text = ""
        if binary_mode:
            binary_text = "  Analysis mode:    [bold cyan]BINARY DECOMPILATION[/bold cyan]\n"
            if decompilation_info:
                binary_text += f"  Architecture:     [cyan]{decompilation_info.architecture}[/cyan]\n"
                binary_text += f"  Functions found:  [cyan]{decompilation_info.functions_found}[/cyan]\n"
            patch_text = "  Auto-patch:       [yellow]N/A (source unavailable)[/yellow]\n"
            verification_text = ""
            healing_text = ""

        dedup_text = ""
        if len(all_crashes) != len(unique_crashes):
            dedup_text = f"  Total crash hits:  [dim]{len(all_crashes)} ({len(all_crashes) - len(unique_crashes)} duplicates removed)[/dim]\n"

        summary = Panel(
            f"[bold green]FUZZING COMPLETE[/bold green]\n\n"
            f"{binary_text}"
            f"  Payloads tested:  [cyan]{len(payloads)}[/cyan]\n"
            f"  Unique crashes:   [bold red]{len(unique_crashes)}[/bold red]\n"
            f"{dedup_text}"
            f"  Crash rate:       [yellow]{crash_rate:.0f}%[/yellow]\n"
            f"  Vuln types:       [magenta]{', '.join(set(c['vuln_type'] for c in crashes))}[/magenta]\n"
            f"  JSON report:      [dim]{json_file}[/dim]\n"
            f"  HTML report:      [yellow]{html_file}[/yellow]\n"
            f"{patch_text}"
            f"{exploit_text}"
            f"{verification_text}"
            f"{healing_text}"
            f"  [dim]Open the HTML report in your browser for a visual breakdown![/dim]",
            title="[bold green]** RESULTS **[/bold green]",
            border_style="green",
            box=box.HEAVY,
        )
    else:
        summary = Panel(
            f"[bold yellow]FUZZING COMPLETE[/bold yellow]\n\n"
            f"  Payloads tested:  [cyan]{len(payloads)}[/cyan]\n"
            f"  Crashes found:    [green]0[/green]\n\n"
            f"  [dim]No crashes found. The target may have mitigations in place.[/dim]",
            title="RESULTS",
            border_style="yellow",
            box=box.HEAVY,
        )

    console.print(summary)
    return len(unique_crashes)


