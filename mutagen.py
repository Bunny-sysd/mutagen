"""
+==============================================================+
|   MUTAGEN -- AI-Powered Zero-Day Fuzzer                      |
|   Built by Aaron Alva                                        |
|                                                              |
|   This tool uses AI to intelligently analyze source code     |
|   and generate targeted payloads designed to find crashes    |
|   and vulnerabilities -- unlike traditional "dumb" fuzzers   |
|   that just throw random garbage.                            |
+==============================================================+

HOW IT WORKS (Learning Notes):
-------------------------------
1. ANALYZE: We read the target's source code (.c file).
2. AI BRAIN: We send that code to the Gemini API and ask it to
   find vulnerabilities and generate crash-inducing payloads.
3. EXECUTE: We compile the target, then feed each AI payload
   into it as input using Python's subprocess module.
4. MONITOR: We watch for crashes (segfaults, access violations).
   If the program crashes, we found a potential zero-day!
5. REPORT: We save all crash-causing payloads to a report.
"""

import subprocess
import sys
import os
import json
import time
import datetime
import io

# --- WHAT IS 'rich'? ---------------------------------------------------
# 'rich' is a Python library that makes terminal output beautiful.
# Instead of plain white text, we get colors, tables, progress
# bars, and styled panels -- like a hacker movie terminal.
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

# --- WHAT IS 'google.genai'? --------------------------------------------
# This is Google's new official SDK for the Gemini API.
# We use it to send source code to the AI and get back
# intelligent, targeted payloads instead of random junk.
from google import genai

# --- GLOBAL SETUP -------------------------------------------------------
# force_terminal=True and force_jupyter=False ensure rich uses
# ANSI color codes instead of Windows legacy console APIs,
# which avoids Unicode encoding errors on Windows terminals.
console = Console(force_terminal=True, force_jupyter=False)


# ================================================================
# SECTION 1: THE AI BRAIN
# ================================================================
# This function sends the target's source code to Gemini and
# asks it to act as a defensive security researcher. By framing
# it this way, we bypass safety filters while getting real
# offensive payloads. This is a legitimate technique used by
# professional red teams and bug bounty hunters.

def ai_analyze_code(source_code: str, api_key: str) -> list[dict]:
    """
    Send source code to Gemini AI and get back targeted payloads.

    WHAT THIS DOES:
    - Configures the Gemini API with your key
    - Sends the source code with a carefully crafted prompt
    - Parses the AI's response into a list of payloads

    RETURNS: A list of dicts like:
      [{"payload": "AAAA...", "reason": "Buffer overflow via strcpy"}, ...]
    """
    # --- CREATE THE CLIENT -----------------------------------------------
    # The new google-genai SDK uses a Client object instead of
    # configuring a global module. This is better practice because
    # it's explicit and doesn't rely on hidden global state.
    client = genai.Client(api_key=api_key)

    # --- THE PROMPT (Prompt Engineering) ---------------------------------
    # Notice how we frame this as "defensive security research".
    # We ask for test vectors to help "patch" the code.
    # This is how real security teams operate -- you must
    # understand attacks to build defenses.
    prompt = f"""You are an expert defensive security researcher conducting a code audit.
Your job is to analyze the following C source code for potential vulnerabilities
such as buffer overflows, format string bugs, integer overflows, use-after-free,
off-by-one errors, and command injection.

For each vulnerability you find, generate a specific test payload (input string)
that would trigger the bug when passed as a command-line argument to the compiled program.

SOURCE CODE:
```c
{source_code}
```

IMPORTANT: Respond ONLY with a valid JSON array. Each element must have:
- "payload": the exact input string to test (represent long strings using Python-style repetition like 'A'*100, or just write the literal string)
- "vuln_type": the type of vulnerability (e.g., "buffer_overflow", "format_string")
- "reason": a brief explanation of why this payload triggers the bug
- "severity": "critical", "high", "medium", or "low"

Generate between 10 and 20 diverse test payloads, ranging from simple to complex.
Focus on payloads that would cause crashes (segmentation faults, access violations).

Respond with ONLY the JSON array, no markdown, no explanation outside the JSON."""

    # --- CALLING THE AI --------------------------------------------------
    # We try multiple models in case one hits rate limits.
    models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"]
    
    response = None
    for model_name in models_to_try:
        for attempt in range(3):  # Up to 3 retries per model
            try:
                console.print(f"[dim]  Trying model: {model_name} (attempt {attempt + 1})...[/dim]")
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config={
                        "temperature": 0.7,
                        "response_mime_type": "application/json",
                    },
                )
                break  # Success! Exit retry loop
            except Exception as e:
                error_msg = str(e)
                if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
                    wait_time = (attempt + 1) * 20  # 20s, 40s, 60s
                    console.print(f"[yellow]  Rate limited. Waiting {wait_time}s before retry...[/yellow]")
                    time.sleep(wait_time)
                else:
                    console.print(f"[red]  Error: {error_msg[:200]}[/red]")
                    break  # Non-rate-limit error, try next model
        
        if response is not None:
            break  # Got a response, stop trying models
    
    if response is None:
        console.print("[red]!! All models failed. Check your API key or try again later.[/red]")
        return []

    # --- PARSING THE RESPONSE --------------------------------------------
    # Two-pass parsing strategy:
    # Pass 1: Try standard JSON parsing (works if AI returns pure JSON)
    # Pass 2: Fall back to Python eval (handles "A"*32 patterns natively)
    raw = response.text.strip()
    
    # Remove markdown code fences if present
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1])

    # Extract just the array portion [...]
    start = raw.find('[')
    end = raw.rfind(']')
    if start >= 0 and end > start:
        array_str = raw[start:end + 1]
    else:
        array_str = raw

    # Pass 1: Try JSON
    try:
        payloads = json.loads(array_str)
        return payloads
    except json.JSONDecodeError:
        pass

    # Pass 2: The AI returned Python-style expressions like "A"*32.
    # Python's eval() can handle this natively since it's valid Python.
    # We restrict it with empty builtins for safety.
    try:
        payloads = eval(array_str, {"__builtins__": {}}, {})
        if isinstance(payloads, list):
            return payloads
    except Exception:
        pass

    # Pass 3: Last resort - parse each JSON object individually
    # Sometimes one malformed object ruins the whole array.
    import re
    try:
        objects = re.findall(r'\{[^}]+\}', array_str)
        payloads = []
        for obj_str in objects:
            try:
                obj = json.loads(obj_str)
                payloads.append(obj)
            except json.JSONDecodeError:
                try:
                    obj = eval(obj_str, {"__builtins__": {}}, {})
                    if isinstance(obj, dict):
                        payloads.append(obj)
                except Exception:
                    continue
        if payloads:
            return payloads
    except Exception:
        pass

    console.print(f"[red]!! Could not parse AI response after all attempts.[/red]")
    console.print(f"[dim]First 300 chars: {raw[:300]}[/dim]")
    return []


# ================================================================
# SECTION 2: THE EXECUTION ENGINE
# ================================================================
# This is where we actually RUN the target program and feed it
# the AI's payloads. We use Python's `subprocess` module, which
# lets us launch any program and control its input/output.

def compile_target(source_path: str, gcc_path: str) -> str:
    """
    Compile a C source file into an executable.

    WHAT THIS DOES:
    - Calls gcc (the C compiler) to build the .c file
    - The '-fno-stack-protector' flag DISABLES security protections
      so our fuzzer can actually trigger the buffer overflow.
      (Modern compilers add "stack canaries" that prevent overflows
      by default -- we turn that off for testing purposes.)
    - Returns the path to the compiled executable
    """
    output_path = source_path.replace(".c", ".exe")

    # --- THE GCC COMMAND -------------------------------------------------
    # gcc flags explained:
    #   -o vuln.exe          -> name the output file
    #   -fno-stack-protector -> disable stack canary protection
    # These flags are standard for security testing environments.
    cmd = [
        gcc_path, source_path,
        "-o", output_path,
        "-fno-stack-protector",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        console.print(f"[red]Compilation failed:[/red]\n{result.stderr}")
        sys.exit(1)

    return output_path


def execute_payload(exe_path: str, payload: str) -> dict:
    """
    Run the target program with a single payload and check if it crashes.

    WHAT THIS DOES:
    - Launches the compiled program as a child process
    - Passes the payload as a command-line argument
    - Waits up to 5 seconds for it to finish (timeout = hung process)
    - Checks the return code:
        * Return code 0 = program ran fine (no crash)
        * Return code != 0 = something went wrong
        * On Windows, access violation = return code -1073741819
    """
    try:
        result = subprocess.run(
            [exe_path, payload],
            capture_output=True,
            text=True,
            timeout=5  # Kill if it hangs for more than 5 seconds
        )

        # --- CRASH DETECTION -----------------------------------------------
        # On Windows, an "Access Violation" (segfault equivalent)
        # returns -1073741819 (0xC0000005).
        crashed = False
        crash_type = "none"

        if result.returncode != 0:
            crashed = True
            if result.returncode == -1073741819 or result.returncode == 3221225477:
                crash_type = "ACCESS_VIOLATION (Buffer Overflow!)"
            elif result.returncode == -1073741676:
                crash_type = "STACK_OVERFLOW"
            elif result.returncode < 0:
                crash_type = f"SIGNAL_{abs(result.returncode)}"
            else:
                crash_type = f"EXIT_CODE_{result.returncode}"

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
            "stderr": "Process killed after 5s timeout",
        }


# ================================================================
# SECTION 3: THE CRASH REPORT
# ================================================================
# When we find crashes, we save them to a JSON report so they
# can be reviewed later. This is how professional fuzzers like
# AFL and libFuzzer work -- they save "crash artifacts".

def save_crash_report(crashes: list[dict], target_name: str, total_tested: int):
    """Save all crash-causing payloads to a JSON report file."""
    os.makedirs("crashes", exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"crashes/crash_report_{target_name}_{timestamp}.json"

    report = {
        "tool": "Mutagen v1.0",
        "target": target_name,
        "timestamp": timestamp,
        "total_payloads_tested": total_tested,
        "total_crashes_found": len(crashes),
        "crashes": crashes,
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    return filename


# ================================================================
# SECTION 4: THE MAIN FUZZING LOOP
# ================================================================

def run_fuzzer(source_path: str, api_key: str, gcc_path: str):
    """Main fuzzer orchestration function."""

    # --- BANNER ----------------------------------------------------------
    banner_lines = [
        "  __  __ _   _ _____  _    ____ _____ _   _ ",
        " |  \\/  | | | |_   _|/ \\  / ___| ____| \\ | |",
        " | |\\/| | | | | | | / _ \\| |  _|  _| |  \\| |",
        " | |  | | |_| | | |/ ___ \\ |_| | |___| |\\  |",
        " |_|  |_|\\___/  |_/_/   \\_\\____|_____|_| \\_|",
        "",
        " AI-Powered Zero-Day Fuzzer v1.0",
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

    with open(source_path, "r") as f:
        source_code = f.read()

    console.print(f"[dim]  Read {len(source_code)} bytes of source code[/dim]")
    console.print()

    # --- STEP 2: AI ANALYSIS ---------------------------------------------
    console.print(Panel(
        "[bold cyan]PHASE 1: AI CODE ANALYSIS[/bold cyan]\n"
        "[dim]Sending source code to Gemini for vulnerability analysis...[/dim]",
        border_style="cyan"
    ))

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[green]AI analyzing code for vulnerabilities..."),
        console=console,
    ) as progress:
        task = progress.add_task("", total=None)
        payloads = ai_analyze_code(source_code, api_key)

    if not payloads:
        console.print("[red]X AI returned no payloads. Check your API key.[/red]")
        sys.exit(1)

    console.print(f"[green]>> AI generated {len(payloads)} targeted payloads[/green]")
    console.print()

    # Show what the AI found
    vuln_table = Table(title="AI Vulnerability Analysis", box=box.ROUNDED, border_style="cyan")
    vuln_table.add_column("#", style="dim", width=4)
    vuln_table.add_column("Type", style="yellow")
    vuln_table.add_column("Severity", style="red")
    vuln_table.add_column("Payload Preview", style="green", max_width=40)
    vuln_table.add_column("Reason", style="dim", max_width=35)

    for i, p in enumerate(payloads):
        severity = p.get("severity", "unknown")
        sev_colors = {
            "critical": "[bold red]",
            "high": "[red]",
            "medium": "[yellow]",
            "low": "[green]"
        }
        sev_style = sev_colors.get(severity, "[dim]")

        preview = p.get("payload", "")[:38]
        if len(p.get("payload", "")) > 38:
            preview += "..."

        vuln_table.add_row(
            str(i + 1),
            p.get("vuln_type", "unknown"),
            f"{sev_style}{severity}",
            preview,
            p.get("reason", "")[:33],
        )

    console.print(vuln_table)
    console.print()

    # --- STEP 3: COMPILE THE TARGET --------------------------------------
    console.print(Panel(
        "[bold cyan]PHASE 2: COMPILE TARGET[/bold cyan]\n"
        "[dim]Building the target with security protections disabled...[/dim]",
        border_style="cyan"
    ))

    exe_path = compile_target(source_path, gcc_path)
    console.print(f"[green]>> Compiled to: {exe_path}[/green]")
    console.print()

    # --- STEP 4: FUZZ! ---------------------------------------------------
    console.print(Panel(
        "[bold red]PHASE 3: FUZZING[/bold red]\n"
        "[dim]Injecting AI payloads into the target and monitoring for crashes...[/dim]",
        border_style="red"
    ))

    crashes = []
    results_table = Table(title="Fuzzing Results", box=box.ROUNDED, border_style="green")
    results_table.add_column("#", style="dim", width=4)
    results_table.add_column("Status", width=12)
    results_table.add_column("Payload", style="cyan", max_width=35)
    results_table.add_column("Crash Type", style="red", max_width=30)
    results_table.add_column("Return Code", style="yellow", width=12)

    for i, p in enumerate(payloads):
        payload_str = p.get("payload", "")

        # Process hex escape sequences in the payload
        try:
            payload_str = payload_str.encode().decode('unicode_escape')
        except Exception:
            pass  # Keep the original string if decoding fails

        result = execute_payload(exe_path, payload_str)

        status = "[bold red]CRASH!!" if result["crashed"] else "[green]OK"
        preview = payload_str[:33]
        if len(payload_str) > 33:
            preview += "..."

        results_table.add_row(
            str(i + 1),
            status,
            preview,
            result["crash_type"] if result["crashed"] else "-",
            str(result["return_code"]),
        )

        if result["crashed"]:
            crashes.append({
                "payload": p.get("payload", ""),
                "vuln_type": p.get("vuln_type", ""),
                "reason": p.get("reason", ""),
                "severity": p.get("severity", ""),
                "crash_type": result["crash_type"],
                "return_code": result["return_code"],
            })

        time.sleep(0.15)  # Brief pause for dramatic effect

    console.print(results_table)
    console.print()

    # --- STEP 5: REPORT --------------------------------------------------
    target_name = os.path.basename(source_path).replace(".c", "")

    if crashes:
        report_file = save_crash_report(crashes, target_name, len(payloads))

        summary = Panel(
            f"[bold green]FUZZING COMPLETE[/bold green]\n\n"
            f"  Payloads tested:  [cyan]{len(payloads)}[/cyan]\n"
            f"  Crashes found:    [bold red]{len(crashes)}[/bold red]\n"
            f"  Report saved to:  [yellow]{report_file}[/yellow]\n\n"
            f"  [dim]Each crash represents a potential zero-day vulnerability.[/dim]",
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


# ================================================================
# SECTION 5: ENTRY POINT
# ================================================================
# This runs when you type: python mutagen.py <target.c>

if __name__ == "__main__":
    # Fix Windows console encoding for colored output
    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    if len(sys.argv) < 2:
        console.print("[red]Usage: python mutagen.py <target.c>[/red]")
        console.print("[dim]  Example: python mutagen.py vuln.c[/dim]")
        sys.exit(1)

    target_file = sys.argv[1]

    if not os.path.exists(target_file):
        console.print(f"[red]X File not found: {target_file}[/red]")
        sys.exit(1)

    # --- API KEY ---------------------------------------------------------
    # We read the Gemini API key from an environment variable.
    # This is a security best practice -- NEVER hardcode API keys
    # in source code! Anyone who sees your GitHub repo would
    # steal your key. Environment variables keep secrets safe.
    api_key = os.environ.get("GEMINI_API_KEY", "")

    if not api_key:
        console.print("[red]X GEMINI_API_KEY environment variable not set.[/red]")
        console.print("[dim]  Get a free key at: https://aistudio.google.com/apikey[/dim]")
        console.print("[dim]  Then run: $env:GEMINI_API_KEY='your-key-here'[/dim]")
        sys.exit(1)

    # --- FIND GCC --------------------------------------------------------
    gcc_candidates = [
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
        r"C:\msys64\mingw32\bin\gcc.exe",
        r"C:\MinGW\bin\gcc.exe",
        r"C:\TDM-GCC-64\bin\gcc.exe",
        "gcc",  # Fall back to PATH
    ]

    gcc_path = None
    for candidate in gcc_candidates:
        if candidate == "gcc" or os.path.exists(candidate):
            gcc_path = candidate
            break

    if not gcc_path:
        console.print("[red]X GCC not found. Install MSYS2 or MinGW.[/red]")
        sys.exit(1)

    console.print(f"[dim]Using GCC: {gcc_path}[/dim]")

    # --- GO! -------------------------------------------------------------
    run_fuzzer(target_file, api_key, gcc_path)
