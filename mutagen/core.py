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


def run_fuzzer(source_path: str, api_key: str, gcc_path: str, max_payloads: int, timeout: int, debug: bool, provider: str = "gemini", model: str = "", delivery_mode: str = "args"):
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
        for retry_attempt in range(1, max_retries + 1):
            console.print(f"[yellow]  ↳ Payload {i+1} failed. Agentic Retry {retry_attempt}/{max_retries} initializing...[/yellow]")
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
        
        patch_file = ""
        exploit_file = ""
        patch_code = ""
        exploit_code = ""
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("AI writing secure C patch...", total=None)
            patch_code = engine.generate_patch(source_code, crashes[0], debug)
            
            if patch_code:
                os.makedirs("patches", exist_ok=True)
                patch_file = f"patches/{target_name}_FIXED.c"
                with open(patch_file, "w", encoding="utf-8") as f:
                    f.write(patch_code)
                    
            progress.update(task, description="[magenta]AI writing Python exploit script...")
            exploit_code = engine.generate_exploit(source_code, crashes[0], exe_path, delivery_mode, debug)
            
            if exploit_code:
                os.makedirs("exploits", exist_ok=True)
                exploit_file = f"exploits/{target_name}_exploit.py"
                with open(exploit_file, "w", encoding="utf-8") as f:
                    f.write(exploit_code)
                    
        if patch_file:
            console.print(f"[green]>> Secure patch saved to: {patch_file}[/green]")
        else:
            console.print("[red]X Failed to generate patch.[/red]")
            
        if exploit_file:
            console.print(f"[green]>> Python exploit saved to: {exploit_file}[/green]\n")
        else:
            console.print("[red]X Failed to generate exploit.[/red]\n")

        json_file, html_file = save_crash_report(crashes, target_name, len(payloads), patch_code, exploit_code)

        patch_text = f"  Patch generated:  [cyan]{patch_file}[/cyan]\n" if patch_file else ""
        exploit_text = f"  Exploit generated:[magenta]{exploit_file}[/magenta]\n" if exploit_file else ""

        # --- PHASE 5: AUTO-PATCH VERIFICATION --------------------------------
        patch_verified = False
        if patch_file:
            console.print(Panel(
                "[bold cyan]PHASE 5: AUTO-PATCH VERIFICATION[/bold cyan]\n"
                "[dim]Mathematically proving the patch works...[/dim]",
                border_style="cyan"
            ))
            
            try:
                patched_exe = compile_target(patch_file, gcc_path)
                console.print(f"[green]>> Compiled patched target: {patched_exe}[/green]")
                
                with Progress(
                    SpinnerColumn(style="cyan"),
                    TextColumn("[cyan]Firing exploit at patched target..."),
                    console=console,
                ) as progress:
                    task = progress.add_task("", total=None)
                    verify_result = execute_payload(patched_exe, crashes[0]["args"], crashes[0].get("input_data", ""), delivery_mode, timeout)
                    
                if verify_result["crashed"]:
                    console.print(f"[bold red]X PATCH FAILED![/bold red] The patched program still crashed: {verify_result['crash_type']}\n")
                else:
                    patch_verified = True
                    console.print("[bold green][+] PATCH VERIFIED SUCCESSFUL![/bold green] The exploit no longer crashes the target.\n")
            except CompilationError as e:
                console.print(f"[bold red]X PATCH COMPILATION FAILED![/bold red] The patched C code contains compiler errors:\n{e}\n")

        verification_text = f"  Verification:     [bold green]VERIFIED SECURE[/bold green]\n" if patch_verified else (f"  Verification:     [bold red]FAILED[/bold red]\n" if patch_file else "")

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

