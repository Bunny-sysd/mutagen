"""Mutagen Batch Runner — run the fuzzer against all targets automatically."""

import os
import glob
import subprocess
import argparse
import sys

from rich.console import Console

console = Console()


def main():
    parser = argparse.ArgumentParser(description="Mutagen Batch Runner")
    parser.add_argument("--max-payloads", type=int, default=3, help="Max payloads per target")
    parser.add_argument("--api-key", help="API Key")
    parser.add_argument("--provider", default="gemini", choices=["gemini", "openai", "ollama"], help="LLM Provider")
    parser.add_argument("--model", default="", help="Specific model to use")
    args = parser.parse_args()

    os.makedirs("crashes", exist_ok=True)
    os.makedirs("patches", exist_ok=True)
    os.makedirs("exploits", exist_ok=True)

    targets = sorted(glob.glob("targets/*.c"))
    if not targets:
        console.print("[red]No targets found in targets/ directory![/red]")
        return

    console.print(f"[bold green]Starting Mutagen Batch Run on {len(targets)} targets...[/bold green]\n")

    successful_exploits = 0

    for idx, target in enumerate(targets):
        target_name = os.path.basename(target)
        console.print(f"[bold cyan]{'=' * 50}[/bold cyan]")
        console.print(f"[bold cyan]TARGET {idx + 1}/{len(targets)}: {target_name}[/bold cyan]")
        console.print(f"[bold cyan]{'=' * 50}[/bold cyan]")

        cmd = [sys.executable, "-m", "mutagen", "--target", target, "--max-payloads", str(args.max_payloads)]
        if args.api_key:
            cmd.extend(["--api-key", args.api_key])
        if args.provider:
            cmd.extend(["--provider", args.provider])
        if args.model:
            cmd.extend(["--model", args.model])

        try:
            result = subprocess.run(cmd, text=True, check=False)
            if result.returncode == 0:
                fixed_file = f"patches/{target_name.replace('.c', '_FIXED.c')}"
                if os.path.exists(fixed_file):
                    successful_exploits += 1
                    console.print(f"[bold green][+] {target_name} exploited and patched![/bold green]\n")
                else:
                    console.print(f"[bold yellow][-] {target_name} analyzed, no crash found.[/bold yellow]\n")
            else:
                console.print(f"[bold red][!] Failed on {target_name} (exit {result.returncode})[/bold red]\n")
        except KeyboardInterrupt:
            console.print("\n[bold red]Batch run interrupted by user.[/bold red]")
            break
        except Exception as e:
            console.print(f"[bold red]Error on {target}: {e}[/bold red]\n")

    console.print(f"\n[bold green]Batch Run Complete![/bold green]")
    console.print(f"[bold]Exploited & patched: {successful_exploits}/{len(targets)} targets.[/bold]")
    console.print(f"Check [cyan]crashes/[/cyan] for HTML reports.")


if __name__ == "__main__":
    main()
