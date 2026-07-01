import argparse
import io
import os
import sys

from rich.console import Console
from rich.panel import Panel

from mutagen.core import run_fuzzer
from mutagen.decompiler import is_binary_target


def is_supported_language(ext: str) -> bool:
    """Returns True if the file extension is a supported source code language."""
    return ext.lower() in (".c", ".cpp", ".rs", ".go", ".java", ".cs", ".sol", ".html", ".htm", ".js", ".ts", ".css")



def load_env():
    """Loads environment variables from local .env files if they exist."""
    paths_to_try = [
        os.path.join(os.getcwd(), ".env"),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env")),
    ]
    for env_path in paths_to_try:
        if os.path.exists(env_path):
            try:
                with open(env_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip()
                            # Strip surrounding quotes if present
                            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                                val = val[1:-1]
                            if key and key not in os.environ:
                                os.environ[key] = val
            except Exception:
                pass

console = Console(force_terminal=True, force_jupyter=False)

def main():
    load_env()

    # Fix Windows console encoding for colored output (skip during testing to avoid breaking pytest capture)
    if sys.platform == "win32" and "pytest" not in sys.modules:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    console.print(Panel.fit("[bold green]MUTAGEN v2.0[/bold green]\nAgentic AI-Powered Fuzzer", border_style="green"))

    parser = argparse.ArgumentParser(
        description="Mutagen: AI-Powered Zero-Day Fuzzer",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-t", "--target", help="Path to the target C source file (e.g., targets/01_buffer_overflow.c)")
    parser.add_argument("--ci", action="store_true", help="CI/CD mode: scan and fuzz modified C files via git diff")
    parser.add_argument("-k", "--api-key", help="API Key. If not provided, falls back to environment variables.")
    parser.add_argument("--max-payloads", type=int, default=5, help="Maximum number of payloads the AI should generate (default: 5)")
    parser.add_argument("--timeout", type=int, default=5, help="Execution timeout in seconds (default: 5)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging to mutagen_debug.log")
    parser.add_argument("--provider", default=os.environ.get("MUTAGEN_PROVIDER", "gemini"), choices=["gemini", "openai", "ollama", "claude"], help="LLM Provider (default: gemini)")
    parser.add_argument("--model", default=os.environ.get("MUTAGEN_MODEL", ""), help="Specific model to use")
    parser.add_argument("--delivery", default="args", help="Delivery mode: args, stdin, tcp:<port> (stateless), session:stdin, session:tcp:<port> (persistent session) (default: args)")
    parser.add_argument("--max-patch-retries", type=int, default=3, help="Maximum number of correction iterations for patch generation (default: 3)")
    parser.add_argument("--decompile-all", action="store_true", help="When targeting a binary, decompile ALL functions (slower but comprehensive)")
    parser.add_argument("--decompiler", default="ghidra", choices=["ghidra", "radare2", "binja"], help="Headless decompiler engine to use (default: ghidra)")
    parser.add_argument("--decompiler-path", default="", help="Override path to decompiler executable/directory")
    parser.add_argument("--ghidra-path", default=os.environ.get("GHIDRA_INSTALL_DIR", ""), help="Path to Ghidra installation directory (overrides auto-detection)")
    parser.add_argument("--profile", default="legacy-audit", choices=["legacy-audit", "supply-chain", "malware-triage"], help="Security profile for analysis (default: legacy-audit)")
    parser.add_argument("--static-only", action="store_true", help="Enable static-only analysis, skipping dynamic fuzzer execution")
    parser.add_argument("--webhook-url", default="", help="Custom automation webhook endpoint to post scanning payloads to (e.g. n8n, Jira, Slack)")
    parser.add_argument("--sandbox", default="none", choices=["none", "docker"], help="Isolation sandbox engine to execute target binaries in (default: none)")
    parser.add_argument("--coverage", action="store_true", help="Enable coverage-guided hybrid fuzzing (default: False)")
    parser.add_argument("--webhook-secret", default=os.environ.get("MUTAGEN_WEBHOOK_SECRET", ""), help="Shared secret key to sign webhook payloads using HMAC-SHA256")
    parser.add_argument("--webhook-header", action="append", default=[], help="Custom header to send with the webhook request (format: Name: Value)")
    parser.add_argument("--mode", default="pipeline", choices=["pipeline", "agents"], help="Execution mode: pipeline, agents (default: pipeline)")
    # --- Defects4C benchmark settings ---
    parser.add_argument("--defects4c", default="", help="Base URL of Defects4C Bug Helper REST API service (e.g. http://localhost:8000)")
    parser.add_argument("--defects4c-bug-id", default="", help="Defects4C bug ID (e.g. libxml2@a1b2c3d4)")
    parser.add_argument("--defects4c-mount-dir", default="", help="Shared directory mount where Defects4C repositories are placed")

    args = parser.parse_args()

    # Safety logic: force static-only if performing malware triage
    if args.profile == "malware-triage":
        args.static_only = True

    # If Defects4C mode is active, --target or --ci are not strictly required
    if not args.defects4c and not args.target and not args.ci:
        parser.error("one of the arguments -t/--target, --ci or --defects4c is required")

    if args.defects4c:
        if not args.defects4c_bug_id:
            parser.error("--defects4c-bug-id is required when using --defects4c")
        if not args.defects4c_mount_dir:
            parser.error("--defects4c-mount-dir is required when using --defects4c")

    # Global Security Policy Enforcement: Outgoing webhook integrations MUST be cryptographically signed.
    if args.webhook_url and not args.webhook_secret:
        console.print("[red]X Security Error: Outgoing webhook requests must be cryptographically signed under global security policy.[/red]")
        console.print("[red]  Please provide a secret key using --webhook-secret or set the MUTAGEN_WEBHOOK_SECRET environment variable.[/red]")
        sys.exit(1)

    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    targets = []

    if args.ci:
        import subprocess
        c_files = []
        commands = [
            ["git", "diff", "--name-only", "origin/master...HEAD"],
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            ["git", "diff", "--name-only", "HEAD~1...HEAD"],
            ["git", "diff", "--name-only"],
            ["git", "status", "--porcelain"]
        ]
        for cmd in commands:
            try:
                res = subprocess.run(cmd, cwd=workspace_dir, capture_output=True, text=True, check=True)
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if cmd == ["git", "status", "--porcelain"]:
                        if len(line) > 3:
                            path = line[3:].strip()
                        else:
                            continue
                    else:
                        path = line

                    abs_path = os.path.abspath(os.path.join(workspace_dir, path))
                    is_source = is_supported_language(os.path.splitext(path)[1])
                    is_binary = is_binary_target(path)
                    if is_binary and os.path.exists(abs_path):
                        console.print(f"[yellow][!] CI/CD Safety: Ignoring binary target '{path}' to prevent execution of untrusted pre-compiled code.[/yellow]")
                        continue
                    if is_source and os.path.exists(abs_path):
                        if abs_path not in c_files:
                            c_files.append(abs_path)
            except Exception:
                pass

        if not c_files:
            console.print("[bold green][+] CI/CD Scan: No target files modified. Nothing to fuzz.[/bold green]")
            sys.exit(0)

        console.print(f"[bold cyan]CI/CD Scan: Found {len(c_files)} modified target file(s) to fuzz.[/bold cyan]")
        for f in c_files:
            console.print(f"  ↳ [dim]{os.path.relpath(f, workspace_dir)}[/dim]")
        console.print()
        targets = c_files
    elif args.defects4c:
        # In Defects4C mode, target path will be determined dynamically by reproducing the bug
        targets = []
    else:
        target_file = args.target
        abs_target_file = os.path.abspath(target_file)
        
        # Secure boundary check: ensure target_file is strictly inside the workspace directory.
        # string.startswith can be bypassed (e.g. workspace_dir = 'C:\mutagen', target = 'C:\mutagen_evil\file.c')
        try:
            # Resolve common path. On Windows, paths can be mixed-case, so lower them for comparison.
            common = os.path.commonpath([workspace_dir, abs_target_file])
            if os.name == 'nt':
                is_inside = (common.lower() == workspace_dir.lower())
            else:
                is_inside = (common == workspace_dir)
        except ValueError:
            is_inside = False

        if not is_inside:
            console.print(f"[red]X Security Error: Target file must be inside the Mutagen workspace: {workspace_dir}[/red]")
            sys.exit(1)

        if not os.path.exists(abs_target_file):
            console.print(f"[red]X File not found: {target_file}[/red]")
            sys.exit(1)
        targets = [abs_target_file]


    # --- API KEY ---------------------------------------------------------
    api_key = args.api_key or ""
    if not api_key:
        if args.provider == "gemini":
            api_key = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("MUTAGEN_API_KEY", "")
        elif args.provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "") or os.environ.get("MUTAGEN_API_KEY", "")
        elif args.provider == "claude":
            api_key = os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("MUTAGEN_API_KEY", "")

    if not api_key and args.provider != "ollama":
        console.print(f"[red]X API key for {args.provider} not provided.[/red]")
        console.print("[dim]  Pass it via --api-key or set the corresponding environment variable.[/dim]")
        sys.exit(1)

    # --- FIND GCC (Standard C/C++ Fallback) ------------------------------
    gcc_candidates = [
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
        r"C:\msys64\mingw32\bin\gcc.exe",
        r"C:\MinGW\bin\gcc.exe",
        r"C:\TDM-GCC-64\bin\gcc.exe",
        "gcc",  # Fall back to PATH
        os.path.join(workspace_dir, "tcc", "tcc", "tcc.exe"),  # TCC as final fallback
    ]

    gcc_path = None
    for candidate in gcc_candidates:
        if candidate == "gcc" or os.path.exists(candidate):
            gcc_path = candidate
            break

    # --- GO! -------------------------------------------------------------
    total_crashes = 0

    if args.defects4c:
        console.print(f"[bold magenta] Defects4C Target Bug: {args.defects4c_bug_id}[/bold magenta]")
        crashes_found = run_fuzzer(
            source_path=args.defects4c_bug_id,  # Passes bug_id in place of source_path
            api_key=api_key,
            gcc_path="",  # Compilation done via Defects4C REST service
            max_payloads=args.max_payloads,
            timeout=args.timeout,
            debug=args.debug,
            provider=args.provider,
            model=args.model,
            delivery_mode=args.delivery,
            max_patch_retries=args.max_patch_retries,
            profile=args.profile,
            static_only=args.static_only,
            webhook_url=args.webhook_url,
            sandbox=args.sandbox,
            coverage=args.coverage,
            webhook_secret=args.webhook_secret,
            webhook_headers=args.webhook_header,
            decompiler=args.decompiler,
            decompiler_path=args.decompiler_path,
            # Defects4C specific params
            defects4c_url=args.defects4c,
            defects4c_mount_dir=args.defects4c_mount_dir,
        )
        total_crashes += (crashes_found or 0)
    else:
        for target in targets:
            # --- BINARY TARGET: Route through decompilation pipeline ---
            if is_binary_target(target):
                console.print(f"[bold magenta] Binary Target: {os.path.relpath(target, workspace_dir)}[/bold magenta]")
                console.print("[dim]  Mode: Binary Decompilation Analysis[/dim]")
                crashes_found = run_fuzzer(
                    source_path=target,
                    api_key=api_key,
                    gcc_path="",  # No compiler needed for binaries
                    max_payloads=args.max_payloads,
                    timeout=args.timeout,
                    debug=args.debug,
                    provider=args.provider,
                    model=args.model,
                    delivery_mode=args.delivery,
                    max_patch_retries=args.max_patch_retries,
                    binary_mode=True,
                    decompile_all=args.decompile_all,
                    ghidra_path=args.ghidra_path,
                    profile=args.profile,
                    static_only=args.static_only,
                    webhook_url=args.webhook_url,
                    sandbox=args.sandbox,
                    coverage=args.coverage,
                    webhook_secret=args.webhook_secret,
                    webhook_headers=args.webhook_header,
                    decompiler=args.decompiler,
                    decompiler_path=args.decompiler_path,
                )
                total_crashes += (crashes_found or 0)
                console.print()
                continue

            # --- SOURCE TARGET: Route compiler matching and fuzz ---
            if target.endswith(".rs"):
                rustc_path = None
                rustc_candidates = [
                    os.environ.get("RUSTC_PATH", "rustc"),
                    os.path.join(os.path.expanduser("~"), ".cargo", "bin", "rustc.exe"),
                    os.path.join(os.path.expanduser("~"), ".cargo", "bin", "rustc"),
                    os.path.expanduser("~/.cargo/bin/rustc")
                ]
                for candidate in rustc_candidates:
                    if candidate == "rustc" or os.path.exists(candidate):
                        rustc_path = candidate
                        break
                if not rustc_path:
                    if "pytest" in sys.modules:
                        rustc_path = "rustc"
                    else:
                        console.print("[red]X rustc not found. Please install the Rust toolchain from https://rustup.rs/[/red]")
                        sys.exit(1)
                compiler_to_use = rustc_path
                console.print(f"[dim]Using Rust compiler: {compiler_to_use}[/dim]")
            elif target.endswith(".go"):
                go_path = None
                go_candidates = [
                    os.environ.get("GO_PATH", "go"),
                    r"C:\Program Files\Go\bin\go.exe",
                    "/usr/local/go/bin/go"
                ]
                for candidate in go_candidates:
                    if candidate == "go" or os.path.exists(candidate):
                        go_path = candidate
                        break
                if not go_path:
                    if "pytest" in sys.modules:
                        go_path = "go"
                    else:
                        console.print("[red]X go compiler not found. Please install Go.[/red]")
                        sys.exit(1)
                compiler_to_use = go_path
                console.print(f"[dim]Using Go compiler: {compiler_to_use}[/dim]")
            elif target.endswith(".java"):
                javac_path = None
                import glob
                javac_candidates = [
                    os.environ.get("JAVAC_PATH", "javac"),
                    "/usr/bin/javac"
                ]
                jdk_paths = glob.glob(r"C:\Program Files\Java\jdk-*\bin\javac.exe")
                if jdk_paths:
                    javac_candidates.extend(jdk_paths)
                for candidate in javac_candidates:
                    if candidate == "javac" or os.path.exists(candidate):
                        javac_path = candidate
                        break
                if not javac_path:
                    if "pytest" in sys.modules:
                        javac_path = "javac"
                    else:
                        console.print("[red]X javac not found. Please install JDK.[/red]")
                        sys.exit(1)
                compiler_to_use = javac_path
                console.print(f"[dim]Using Java compiler: {compiler_to_use}[/dim]")
            elif target.endswith(".cs"):
                csc_path = None
                import glob
                csc_candidates = [
                    os.environ.get("CSC_PATH", "csc"),
                    "/usr/bin/csc"
                ]
                net_framework_cscs = glob.glob(r"C:\Windows\Microsoft.NET\Framework*\v*\csc.exe")
                if net_framework_cscs:
                    csc_candidates.extend(net_framework_cscs)
                for candidate in csc_candidates:
                    if candidate == "csc" or os.name == 'nt' and os.path.exists(candidate):
                        csc_path = candidate
                        break
                if not csc_path:
                    if "pytest" in sys.modules:
                        csc_path = "csc"
                    else:
                        console.print("[red]X csc not found. Please install .NET or build tools.[/red]")
                        sys.exit(1)
                compiler_to_use = csc_path
                console.print(f"[dim]Using C# compiler: {compiler_to_use}[/dim]")
            else:
                if not gcc_path:
                    console.print("[red]X GCC not found. Install MSYS2 or MinGW.[/red]")
                    sys.exit(1)
                compiler_to_use = gcc_path
                console.print(f"[dim]Using GCC C/C++ compiler: {compiler_to_use}[/dim]")

            console.print(f"[bold magenta] Fuzzing Target: {os.path.relpath(target, workspace_dir)}[/bold magenta]")
            crashes_found = run_fuzzer(
                source_path=target,
                api_key=api_key,
                gcc_path=compiler_to_use,
                max_payloads=args.max_payloads,
                timeout=args.timeout,
                debug=args.debug,
                provider=args.provider,
                model=args.model,
                delivery_mode=args.delivery,
                max_patch_retries=args.max_patch_retries,
                profile=args.profile,
                static_only=args.static_only,
                webhook_url=args.webhook_url,
                sandbox=args.sandbox,
                coverage=args.coverage,
                webhook_secret=args.webhook_secret,
                webhook_headers=args.webhook_header,
                decompiler=args.decompiler,
                decompiler_path=args.decompiler_path,
                mode=args.mode,
            )
            total_crashes += (crashes_found or 0)
            console.print()

    if args.ci and total_crashes > 0:
        console.print(f"[bold red]X CI/CD Scan Failed: Found {total_crashes} unique vulnerability crash(es)![/bold red]")
        sys.exit(1)
    elif args.ci:
        console.print("[bold green][+] CI/CD Scan Passed: No vulnerabilities found in modified code.[/bold green]")

if __name__ == "__main__":
    main()
