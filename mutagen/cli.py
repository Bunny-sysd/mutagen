import sys
import os
import io
import argparse
from rich.console import Console
from rich.panel import Panel

from mutagen.core import run_fuzzer

def load_env():
    """Loads environment variables from local .env files if they exist."""
    paths_to_try = [
        os.path.join(os.getcwd(), ".env"),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env")),
    ]
    for env_path in paths_to_try:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
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
    
    parser.add_argument("-t", "--target", required=True, help="Path to the target C source file (e.g., targets/01_buffer_overflow.c)")
    parser.add_argument("-k", "--api-key", help="API Key. If not provided, falls back to environment variables.")
    parser.add_argument("--max-payloads", type=int, default=5, help="Maximum number of payloads the AI should generate (default: 5)")
    parser.add_argument("--timeout", type=int, default=5, help="Execution timeout in seconds (default: 5)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging to mutagen_debug.log")
    parser.add_argument("--provider", default=os.environ.get("MUTAGEN_PROVIDER", "gemini"), choices=["gemini", "openai", "ollama", "claude"], help="LLM Provider (default: gemini)")
    parser.add_argument("--model", default=os.environ.get("MUTAGEN_MODEL", ""), help="Specific model to use")
    parser.add_argument("--delivery", default="args", help="Delivery mode: args, stdin, tcp:<port> (default: args)")
    parser.add_argument("--max-patch-retries", type=int, default=3, help="Maximum number of correction iterations for patch generation (default: 3)")
    
    args = parser.parse_args()

    target_file = args.target

    # Path Traversal Security Check
    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    abs_target_file = os.path.abspath(target_file)
    if not abs_target_file.startswith(workspace_dir):
        console.print(f"[red]X Security Error: Target file must be inside the Mutagen workspace: {workspace_dir}[/red]")
        sys.exit(1)

    if not os.path.exists(abs_target_file):
        console.print(f"[red]X File not found: {target_file}[/red]")
        sys.exit(1)

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
        console.print(f"[dim]  Pass it via --api-key or set the corresponding environment variable.[/dim]")
        sys.exit(1)

    # --- FIND GCC --------------------------------------------------------
    gcc_candidates = [
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
        r"C:\msys64\mingw32\bin\gcc.exe",
        r"C:\MinGW\bin\gcc.exe",
        r"C:\TDM-GCC-64\bin\gcc.exe",
        "gcc",  # Fall back to PATH
        r"c:\mutagen\tcc\tcc\tcc.exe",  # TCC as final fallback
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
    run_fuzzer(
        source_path=abs_target_file, 
        api_key=api_key, 
        gcc_path=gcc_path, 
        max_payloads=args.max_payloads, 
        timeout=args.timeout, 
        debug=args.debug,
        provider=args.provider,
        model=args.model,
        delivery_mode=args.delivery,
        max_patch_retries=args.max_patch_retries
    )

if __name__ == "__main__":
    main()
