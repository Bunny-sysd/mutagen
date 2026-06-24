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


def run_fuzzer(source_path: str, api_key: str, gcc_path: str, max_payloads: int, timeout: int, debug: bool, provider: str = "gemini", model: str = "", delivery_mode: str = "args", max_patch_retries: int = 3, binary_mode: bool = False, decompile_all: bool = False, ghidra_path: str = "", profile: str = "legacy-audit", static_only: bool = False, webhook_url: str = "", sandbox: str = "none", coverage: bool = False, webhook_secret: str = "", webhook_headers: list[str] = None, decompiler: str = "ghidra", decompiler_path: str = ""):
    """Main fuzzer orchestration function."""
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
        else:
            language = "c"
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

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[green]AI analyzing code for vulnerabilities..."),
        console=console,
    ) as progress:
        task = progress.add_task("", total=None)
        payloads = engine.analyze_code(source_code, max_payloads, delivery_mode, debug, profile=profile)

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
        for ext_to_strip in (".rs", ".cpp", ".c"):
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
                r_input = rp.get("input_data", "")
                if isinstance(r_args, str):
                    r_args = [r_args]
                r_args = [str(a) for a in r_args]

                # Check if this refined payload has already been executed in this run
                r_key = (tuple(r_args), r_input or "")
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


