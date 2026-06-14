import os
import sys
import time
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

from mutagen.engines import get_engine
from mutagen.compiler import compile_target, CompilationError
from mutagen.executor import execute_payload
from mutagen.reporter import save_crash_report
from mutagen.mutators import generate_fallback_payloads

console = Console(force_terminal=True, force_jupyter=False)


def _crash_signature(crash: dict) -> str:
    """Generate a deduplication key from a crash result."""
    return f"{crash['crash_type']}::{crash['return_code']}::{crash.get('vuln_type', '')}"


def run_fuzzer(source_path: str, api_key: str, gcc_path: str, max_payloads: int, timeout: int, debug: bool, provider: str = "gemini", model: str = "", delivery_mode: str = "args", max_patch_retries: int = 3):
    """Main fuzzer orchestration function."""
    engine = get_engine(provider, api_key, model, debug, console)

    # --- BANNER ----------------------------------------------------------
    banner_lines = [
        "  __  __ _   _ _____  _    ____ _____ _   _ ",
        " |  \\/  | | | |_   _|/ \\  / ___| ____| \\ | |",
        " | |\\/| | | | | | | / _ \\| |  _|  _| |  \\| |",
        " | |  | | |_| | | |/ ___ \\ |_| | |___| |\\  |",
        " |_|  |_|\\___/  |_/_/   \\_\\____|_____|_| \\_|",
        "",
        " AI-Powered Zero-Day Fuzzer v2.0",
        " by Aaron Alva",
    ]
    banner = Text()
    for line in banner_lines[:5]:
        banner.append(line + "\n", style="bold green")
    banner.append("\n", style="dim")
    banner.append(banner_lines[6] + "\n", style="dim white")
    banner.append(banner_lines[7], style="dim cyan")

    console.print(Panel(banner, border_style="green", box=box.HEAVY))
    console.print()

    # --- STEP 1: READ THE TARGET SOURCE CODE -----------------------------
    console.print(f"[cyan]> TARGET:[/cyan] {source_path}")

    with open(source_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    console.print(f"[dim]  Read {len(source_code)} bytes of source code[/dim]")
    console.print()

    # --- STEP 2: AI ANALYSIS ---------------------------------------------
    console.print(Panel(
        f"[bold cyan]PHASE 1: AI CODE ANALYSIS ({delivery_mode.upper()} mode)[/bold cyan]\n"
        "[dim]Sending source code to for vulnerability analysis...[/dim]",
        border_style="cyan"
    ))

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[green]AI analyzing code for vulnerabilities..."),
        console=console,
    ) as progress:
        task = progress.add_task("", total=None)
        payloads = engine.analyze_code(source_code, max_payloads, delivery_mode, debug)

    if not payloads:
        console.print("[yellow]⚠ AI returned no payloads (possible refusal, rate-limit, or network error).[/yellow]")
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

    # --- STEP 3: COMPILE THE TARGET --------------------------------------
    console.print(Panel(
        "[bold cyan]PHASE 2: COMPILE TARGET[/bold cyan]\n"
        "[dim]Building the target with security protections disabled...[/dim]",
        border_style="cyan"
    ))

    try:
        exe_path = compile_target(source_path, gcc_path)
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

        result = execute_payload(exe_path, args, input_data, delivery_mode, timeout)
        return {
            "index": i,
            "payload": p,
            "args": args,
            "input_data": input_data,
            "result": result,
        }

    # --- Parallel Phase: fire all payloads concurrently ---
    worker_count = min(4, len(payloads))
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
            else:
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
    max_retries = 2
    for i, original_p, last_result, last_args, last_input in needs_retry:
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
                r_args = rp.get("args", [])
                r_input = rp.get("input_data", "")
                if isinstance(r_args, str):
                    r_args = [r_args]
                r_args = [str(a) for a in r_args]

                result = execute_payload(exe_path, r_args, r_input, delivery_mode, timeout)

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

    console.print(results_table)
    console.print()

    # --- STEP 5: REPORT --------------------------------------------------
    target_name = os.path.basename(source_path).replace(".c", "")
    crash_rate = (len(all_crashes)/len(payloads)*100) if payloads else 0

    # Use unique_crashes for patching/exploit (most interesting distinct bugs)
    crashes = unique_crashes

    if crashes:
        # --- AUTO-PATCH & AEG GENERATION -------------------------------------
        console.print(Panel(
            "[bold cyan]PHASE 4: AUTO-PATCH & EXPLOIT GENERATION[/bold cyan]\n"
            "[dim]Asking AI to generate a secure fix and Python exploit...[/dim]",
            border_style="cyan"
        ))
        
        patch_file = f"patches/{target_name}_FIXED.c"
        exploit_file = ""
        patch_code = ""
        exploit_code = ""
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]{task.description}"),
            console=console,
        ) as progress:
            progress.update(progress.add_task("[magenta]AI writing Python exploit script..."), total=None)
            exploit_code = engine.generate_exploit(source_code, crashes[0], exe_path, delivery_mode, debug)
            
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
        patch_verified = False
        retries_used = 0
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
                console.print(f"[green]    [+] Patched target compiled successfully[/green]")
                
                with Progress(
                    SpinnerColumn(style="cyan"),
                    TextColumn("[cyan]    Firing exploit at patched target..."),
                    console=console,
                ) as progress:
                    task = progress.add_task("", total=None)
                    verify_result = execute_payload(patched_exe, crashes[0]["args"], crashes[0].get("input_data", ""), delivery_mode, timeout)
                    
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
        json_file, html_file = save_crash_report(crashes, target_name, len(payloads), patch_code, exploit_code)

        patch_text = f"  Patch generated:  [cyan]{patch_file}[/cyan]\n" if patch_file else ""
        exploit_text = f"  Exploit generated:[magenta]{exploit_file}[/magenta]\n" if exploit_file else ""
        verification_text = f"  Verification:     [bold green]VERIFIED SECURE[/bold green]\n" if patch_verified else (f"  Verification:     [bold red]FAILED[/bold red]\n" if patch_file else "")
        
        healing_text = ""
        if patch_file:
            if patch_verified:
                healing_text = f"  Self-healing:     [green]Success (used {retries_used} retries)[/green]\n"
            else:
                healing_text = f"  Self-healing:     [red]Failed (used {retries_used} retries)[/red]\n"

        dedup_text = ""
        if len(all_crashes) != len(unique_crashes):
            dedup_text = f"  Total crash hits:  [dim]{len(all_crashes)} ({len(all_crashes) - len(unique_crashes)} duplicates removed)[/dim]\n"

        summary = Panel(
            f"[bold green]FUZZING COMPLETE[/bold green]\n\n"
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

