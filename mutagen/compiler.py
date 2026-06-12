import os
import subprocess
import sys
from rich.console import Console

console = Console(force_terminal=True, force_jupyter=False)

def compile_target(source_path: str, gcc_path: str) -> str:
    """Compile C target file using the provided gcc path."""
    # Dynamically determine output extension based on OS
    if os.name == 'nt':
        output_path = source_path.replace(".c", ".exe")
    else:
        output_path = source_path.replace(".c", ".out")
        
    result = subprocess.run([gcc_path, "-o", output_path, source_path], capture_output=True, text=True)

    if result.returncode != 0:
        console.print(f"[red]Compilation failed:[/red]\n{result.stderr}")
        sys.exit(1)

    return output_path
