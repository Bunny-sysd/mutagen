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
            env = os.environ.copy()
            gcc_dir = os.path.dirname(gcc_path)
            if gcc_dir:
                env["PATH"] = gcc_dir + os.pathsep + env.get("PATH", "")
                
            res = subprocess.run(
                [gcc_path, "-fsanitize=address,undefined", "-o", dummy_out, dummy_c],
                capture_output=True,
                text=True,
                timeout=5,
                env=env
            )
            return res.returncode == 0
        except Exception:
            return False

class CompilationError(Exception):
    """Exception raised when C compilation fails."""
    pass

def compile_target(source_path: str, gcc_path: str, coverage: bool = False) -> str:
    """Compile C/C++ or Rust target file using the provided compiler path."""
    ext = os.path.splitext(source_path)[1].lower()
    
    if ext == ".go":
        output_path = source_path.replace(".go", ".exe" if os.name == 'nt' else ".out")
        compile_args = [gcc_path, "build", "-o", output_path, source_path]
        result = subprocess.run(compile_args, capture_output=True, text=True)
        if result.returncode != 0:
            raise CompilationError(result.stderr or result.stdout)
        return output_path

    elif ext == ".java":
        class_name = os.path.splitext(os.path.basename(source_path))[0]
        if os.name == 'nt':
            output_path = source_path.replace(".java", ".bat")
        else:
            output_path = source_path.replace(".java", ".sh")
            
        compile_args = [gcc_path, source_path]
        
        env = os.environ.copy()
        javac_dir = os.path.dirname(gcc_path)
        if javac_dir:
            env["PATH"] = javac_dir + os.pathsep + env.get("PATH", "")
            
        result = subprocess.run(compile_args, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise CompilationError(result.stderr or result.stdout)
            
        if os.name == 'nt':
            wrapper_content = f'@echo off\njava -cp "%~dp0" {class_name} %*\n'
        else:
            wrapper_content = f'#!/bin/sh\njava -cp "$(dirname "$0")" {class_name} "$@"\n'
            
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(wrapper_content)
            
        if os.name != 'nt':
            os.chmod(output_path, 0o755)
            
        return output_path

    elif ext == ".cs":
        output_path = source_path.replace(".cs", ".exe" if os.name == 'nt' else ".out")
        compile_args = [gcc_path, f"/out:{output_path}" if os.name == 'nt' else f"-out:{output_path}", source_path]
        
        env = os.environ.copy()
        csc_dir = os.path.dirname(gcc_path)
        if csc_dir:
            env["PATH"] = csc_dir + os.pathsep + env.get("PATH", "")
            
        result = subprocess.run(compile_args, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise CompilationError(result.stderr or result.stdout)
        return output_path

    elif source_path.endswith(".rs"):
        # Dynamically determine output extension based on OS
        if os.name == 'nt':
            output_path = source_path.replace(".rs", ".exe")
        else:
            output_path = source_path.replace(".rs", ".out")
            
        compile_args = [gcc_path, "-o", output_path, source_path]
        
        # Add cargo/rustc bin directory to PATH if available
        env = os.environ.copy()
        rustc_dir = os.path.dirname(gcc_path)
        if rustc_dir:
            env["PATH"] = rustc_dir + os.pathsep + env.get("PATH", "")
            
        result = subprocess.run(compile_args, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise CompilationError(result.stderr)
        return output_path
        
    # C/C++ path
    # Dynamically determine output extension based on OS
    if os.name == 'nt':
        output_path = source_path.replace(".c", ".exe").replace(".cpp", ".exe")
    else:
        output_path = source_path.replace(".c", ".out").replace(".cpp", ".out")
        
    compile_source_path = source_path
    temp_instrumented = None
    
    if coverage:
        try:
            from mutagen.instrumenter import instrument_c_source
            with open(source_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            instrumented_code, total_blocks = instrument_c_source(content)
            console.print(f"[cyan]  Coverage feedback enabled! Instrumented {total_blocks} basic blocks.[/cyan]")
            
            temp_instrumented = source_path.replace(".c", ".instrumented.c").replace(".cpp", ".instrumented.cpp")
            with open(temp_instrumented, "w", encoding="utf-8") as f:
                f.write(instrumented_code)
            compile_source_path = temp_instrumented
        except Exception as e:
            console.print(f"[yellow]  ⚠ Warning: Source-level instrumentation failed: {e}. Falling back to standard compilation.[/yellow]")
            compile_source_path = source_path
            temp_instrumented = None
        
    # Check if sanitizers are supported
    use_sanitizers = check_sanitizer_support(gcc_path)
    compile_args = [gcc_path]
    if use_sanitizers:
        console.print("[yellow]  ASan/UBSan support detected! Injecting compiler instrumentation flags...[/yellow]")
        compile_args.extend(["-fsanitize=address,undefined"])
    else:
        console.print("[dim]  Sanitizers not supported (or using TCC). Compiling standard binary...[/dim]")
        
    compile_args.extend(["-o", output_path, compile_source_path])
    
    # MinGW/MSYS2 needs explicit linking for Winsock
    if os.name == 'nt' and "tcc" not in os.path.basename(gcc_path).lower():
        try:
            with open(source_path, "r", encoding="utf-8") as f:
                content = f.read()
            if "winsock2.h" in content:
                compile_args.append("-lws2_32")
        except Exception:
            pass
            
    # Add compiler directory to PATH so gcc can resolve sub-tools (as.exe, ld.exe, etc.)
    env = os.environ.copy()
    gcc_dir = os.path.dirname(gcc_path)
    if gcc_dir:
        env["PATH"] = gcc_dir + os.pathsep + env.get("PATH", "")
        
    result = subprocess.run(compile_args, capture_output=True, text=True, env=env)

    # Clean up temp instrumented source
    if temp_instrumented and os.path.exists(temp_instrumented):
        try:
            os.remove(temp_instrumented)
        except Exception:
            pass

    if result.returncode != 0:
        raise CompilationError(result.stderr)

    return output_path

