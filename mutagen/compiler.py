import os
import subprocess
import sys
import tempfile
from rich.console import Console

console = Console(force_terminal=True, force_jupyter=False)

def check_sanitizer_support(gcc_path: str) -> bool:
    """Check if the compiler supports address and undefined behavior sanitizers."""
    if "tcc" in os.path.basename(gcc_path).lower():
        # Tiny C Compiler does not support sanitizers
        return False
        
    # Compile a minimal program in a temporary directory to check flag compatibility
    with tempfile.TemporaryDirectory() as tmpdir:
        dummy_c = os.path.join(tmpdir, "test_asan.c")
        dummy_out = os.path.join(tmpdir, "test_asan.exe" if os.name == "nt" else "test_asan.out")
        with open(dummy_c, "w") as f:
            f.write("int main() { return 0; }\n")
            
        try:
            res = subprocess.run(
                [gcc_path, "-fsanitize=address,undefined", "-o", dummy_out, dummy_c],
                capture_output=True,
                text=True,
                timeout=5
            )
            return res.returncode == 0
        except Exception:
            return False

class CompilationError(Exception):
    """Exception raised when C compilation fails."""
    pass

def compile_target(source_path: str, gcc_path: str) -> str:
    """Compile C target file using the provided gcc path, enabling ASan if supported."""
    # Dynamically determine output extension based on OS
    if os.name == 'nt':
        output_path = source_path.replace(".c", ".exe")
    else:
        output_path = source_path.replace(".c", ".out")
        
    # Check if sanitizers are supported
    use_sanitizers = check_sanitizer_support(gcc_path)
    compile_args = [gcc_path]
    if use_sanitizers:
        console.print("[yellow]  ASan/UBSan support detected! Injecting compiler instrumentation flags...[/yellow]")
        compile_args.extend(["-fsanitize=address,undefined"])
    else:
        console.print("[dim]  Sanitizers not supported (or using TCC). Compiling standard binary...[/dim]")
        
    compile_args.extend(["-o", output_path, source_path])
    result = subprocess.run(compile_args, capture_output=True, text=True)

    if result.returncode != 0:
        raise CompilationError(result.stderr)

    return output_path

