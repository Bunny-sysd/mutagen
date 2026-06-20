"""
Mutagen Decompiler Module
=========================
Integrates Ghidra's headless analyzer to decompile compiled binaries
(.exe, .elf, .dll, .so) into pseudo-C source code for AI analysis.

Enterprise Use Case:
    Supply chain security — analyze third-party binaries for vulnerabilities
    before deploying them to production, even without access to source code.
"""

import os
import sys
import glob
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from rich.console import Console

console = Console(force_terminal=True, force_jupyter=False)

# Binary file extensions that Mutagen can decompile
BINARY_EXTENSIONS = {".exe", ".elf", ".o", ".dll", ".so", ".bin", ".sys"}


class DecompilationError(Exception):
    """Raised when binary decompilation fails."""
    pass


@dataclass
class DecompilationResult:
    """Holds the results of a binary decompilation."""
    pseudo_source: str = ""
    functions_found: int = 0
    architecture: str = "unknown"
    binary_format: str = "unknown"
    binary_path: str = ""
    decompiler_used: str = "ghidra"


def is_binary_target(file_path: str) -> bool:
    """Check if the given file path is a compiled binary (not source code)."""
    ext = os.path.splitext(file_path)[1].lower()
    return ext in BINARY_EXTENSIONS


def ensure_compatible_java_home():
    """
    Ensure a compatible Java version (JDK 21+) is set in JAVA_HOME.
    If JAVA_HOME is not set, or points to an incompatible version,
    automatically search standard system paths to locate a valid JDK 21+ installation
    and set os.environ['JAVA_HOME'] for current and child processes.
    """
    current_java_home = os.environ.get("JAVA_HOME", "")
    
    def is_valid_java_21_home(java_home_dir: str) -> bool:
        if not java_home_dir or not os.path.isdir(java_home_dir):
            return False
        java_bin = os.path.join(java_home_dir, "bin", "java.exe" if sys.platform == "win32" else "java")
        if not os.path.exists(java_bin):
            return False
        try:
            res = subprocess.run([java_bin, "-version"], capture_output=True, text=True, timeout=5)
            version_text = (res.stderr or "") + (res.stdout or "")
            return any(f'"{v}.' in version_text or f' {v}.' in version_text or f'version "{v}"' in version_text or f'openjdk {v}' in version_text.lower() for v in range(21, 30))
        except Exception:
            return False

    # Check current JAVA_HOME first
    if is_valid_java_21_home(current_java_home):
        return

    # Gather candidates from standard directories
    candidates = []
    
    if sys.platform == "win32":
        roots = [
            r"C:\Program Files\Microsoft",
            r"C:\Program Files\Java",
            r"C:\Program Files\Eclipse Foundation",
            r"C:\Program Files\Eclipse Adoptium",
            r"C:\Program Files\Amazon Corretto",
            r"C:\Program Files\BellSoft",
            r"C:\Program Files\Semeru",
            r"C:\Program Files\RedHat",
        ]
        for root in roots:
            if os.path.isdir(root):
                for path in glob.glob(os.path.join(root, "*")):
                    if os.path.isdir(path):
                        name = os.path.basename(path).lower()
                        if any(str(v) in name for v in range(21, 30)):
                            candidates.append(path)
    elif sys.platform == "darwin":
        roots = [
            "/Library/Java/JavaVirtualMachines",
            "/System/Library/Java/JavaVirtualMachines",
        ]
        for root in roots:
            if os.path.isdir(root):
                for path in glob.glob(os.path.join(root, "*.jdk")):
                    name = os.path.basename(path).lower()
                    if any(str(v) in name for v in range(21, 30)):
                        home_path = os.path.join(path, "Contents", "Home")
                        if os.path.isdir(home_path):
                            candidates.append(home_path)
    else:
        roots = [
            "/usr/lib/jvm",
            "/usr/lib64/jvm",
            "/usr/local/java",
            "/usr/java",
        ]
        for root in roots:
            if os.path.isdir(root):
                for path in glob.glob(os.path.join(root, "*")):
                    if os.path.isdir(path):
                        name = os.path.basename(path).lower()
                        if any(str(v) in name for v in range(21, 30)):
                            candidates.append(path)

    # Check if 'java' on PATH is Java 21+ and use its grandparent as JAVA_HOME
    path_java = shutil.which("java")
    if path_java:
        try:
            real_java = os.path.realpath(path_java)
            grandparent = os.path.dirname(os.path.dirname(real_java))
            if grandparent not in candidates:
                candidates.append(grandparent)
        except Exception:
            pass

    # Validate candidates and set JAVA_HOME if any match
    for cand in candidates:
        if is_valid_java_21_home(cand):
            os.environ["JAVA_HOME"] = cand
            console.print(f"[green]>> Automatically resolved compatible JAVA_HOME: {cand}[/green]")
            return

    # If we still don't have a valid JAVA_HOME, print warning
    new_java_home = os.environ.get("JAVA_HOME", "")
    if not is_valid_java_21_home(new_java_home):
        console.print("[yellow]>> WARNING: No compatible Java 21+ (JDK 21) installation was auto-detected.[/yellow]")
        console.print("[yellow]   Ghidra 12.x requires JDK 21+. Please install JDK 21+ or set JAVA_HOME.[/yellow]")


def find_ghidra(ghidra_path_override: str = "") -> str:
    """
    Locate the Ghidra installation directory.

    Search order:
      1. Explicit path override (--ghidra-path CLI flag)
      2. GHIDRA_INSTALL_DIR environment variable
      3. Common installation directories (Windows & Linux)
      4. analyzeHeadless on PATH

    Returns:
        Path to the analyzeHeadless script/batch file.

    Raises:
        DecompilationError: If Ghidra cannot be found.
    """
    ensure_compatible_java_home()
    # 1. Explicit override
    if ghidra_path_override:
        headless = _resolve_headless(ghidra_path_override)
        if headless:
            return headless
        raise DecompilationError(
            f"Ghidra not found at specified path: {ghidra_path_override}\n"
            f"Expected to find 'analyzeHeadless' script in the 'support' subdirectory."
        )

    # 2. Environment variable
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if env_dir:
        headless = _resolve_headless(env_dir)
        if headless:
            return headless

    # 3. Common installation directories
    common_dirs = []
    if sys.platform == "win32":
        common_dirs = [
            r"C:\ghidra",
            r"C:\Program Files\Ghidra",
            r"C:\Program Files (x86)\Ghidra",
            os.path.expanduser(r"~\ghidra"),
        ]
        # Also search for versioned directories like C:\ghidra_11.3.1_PUBLIC
        for drive in ["C:", "D:"]:
            pattern = os.path.join(drive, os.sep, "ghidra_*")
            common_dirs.extend(glob.glob(pattern))
            pattern2 = os.path.join(drive, os.sep, "Program Files", "ghidra_*")
            common_dirs.extend(glob.glob(pattern2))
    else:
        common_dirs = [
            "/opt/ghidra",
            "/usr/local/ghidra",
            "/usr/share/ghidra",
            os.path.expanduser("~/ghidra"),
        ]
        # Versioned directories under /opt
        common_dirs.extend(glob.glob("/opt/ghidra_*"))
        common_dirs.extend(glob.glob(os.path.expanduser("~/ghidra_*")))

    for directory in common_dirs:
        if os.path.isdir(directory):
            headless = _resolve_headless(directory)
            if headless:
                return headless

    # 4. Check PATH
    script_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
    path_result = shutil.which(script_name)
    if path_result:
        return path_result

    raise DecompilationError(
        "Ghidra is not installed or could not be found.\n\n"
        "To fix this, do one of:\n"
        "  1. Set the GHIDRA_INSTALL_DIR environment variable\n"
        "  2. Use --ghidra-path <path> on the command line\n"
        "  3. Install Ghidra to a standard location (C:\\ghidra or /opt/ghidra)\n\n"
        "Download Ghidra (free, open-source) from:\n"
        "  https://ghidra-sre.org/"
    )


def _resolve_headless(ghidra_dir: str) -> str | None:
    """Given a Ghidra install directory, find the analyzeHeadless script."""
    if sys.platform == "win32":
        candidates = [
            os.path.join(ghidra_dir, "support", "analyzeHeadless.bat"),
            os.path.join(ghidra_dir, "analyzeHeadless.bat"),
        ]
    else:
        candidates = [
            os.path.join(ghidra_dir, "support", "analyzeHeadless"),
            os.path.join(ghidra_dir, "analyzeHeadless"),
        ]

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def _generate_ghidra_postscript(output_file: str, all_functions: bool = False) -> str:
    """
    Generate a Ghidra PostScript (Java) that exports decompiled pseudo-C.

    The script is written to a temporary file and passed to analyzeHeadless.
    It iterates over functions in the binary and writes their decompiled
    representation to the specified output file.
    """
    # Ghidra scripts are written in Java and extend GhidraScript
    script = f'''//Decompile all functions and write pseudo-C to output file.
//@category Mutagen
//@description Export decompiled C for Mutagen analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import java.io.FileWriter;
import java.io.PrintWriter;

public class MutagenExportDecompiled extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        String outputPath = "{output_file.replace(os.sep, '/')}";
        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));

        Program program = currentProgram;
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        FunctionManager funcMgr = program.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);

        // Write binary metadata header
        writer.println("// ============================================");
        writer.println("// MUTAGEN DECOMPILED OUTPUT");
        writer.println("// Binary: " + program.getExecutablePath());
        writer.println("// Format: " + program.getExecutableFormat());
        writer.println("// Architecture: " + program.getLanguage().getProcessor().toString());
        writer.println("// Compiler: " + program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        writer.println("// ============================================");
        writer.println();

        int functionCount = 0;
        boolean allFunctions = {"true" if all_functions else "false"};

        while (funcs.hasNext()) {{
            Function func = funcs.next();

            // Skip thunks and external functions
            if (func.isThunk() || func.isExternal()) {{
                continue;
            }}

            // If not --decompile-all, only decompile main and functions it calls
            if (!allFunctions) {{
                String name = func.getName().toLowerCase();
                if (!name.equals("main") && !name.equals("_main") &&
                    !name.startsWith("entry") && !isCalledByMain(funcMgr, func)) {{
                    continue;
                }}
            }}

            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {{
                String code = results.getDecompiledFunction().getC();
                if (code != null && !code.trim().isEmpty()) {{
                    writer.println("// --- Function: " + func.getName() + " @ " + func.getEntryPoint() + " ---");
                    writer.println(code);
                    writer.println();
                    functionCount++;
                }}
            }}
        }}

        decomp.dispose();
        writer.println("// --- Total functions decompiled: " + functionCount + " ---");
        writer.close();

        println("[Mutagen] Decompiled " + functionCount + " functions to: " + outputPath);
    }}

    private boolean isCalledByMain(FunctionManager funcMgr, Function target) {{
        // Simple heuristic: check if 'main' or '_main' references this function
        FunctionIterator allFuncs = funcMgr.getFunctions(true);
        while (allFuncs.hasNext()) {{
            Function f = allFuncs.next();
            String name = f.getName().toLowerCase();
            if (name.equals("main") || name.equals("_main") || name.startsWith("entry")) {{
                // Check if this function's body references the target
                if (f.getBody().contains(target.getEntryPoint())) {{
                    return true;
                }}
            }}
        }}
        return false;
    }}
}}
'''
    return script


def decompile_binary(
    binary_path: str,
    ghidra_headless: str,
    all_functions: bool = False,
    timeout: int = 120,
) -> DecompilationResult:
    """
    Decompile a binary using Ghidra's headless analyzer.

    Args:
        binary_path: Path to the compiled binary (.exe, .elf, etc.)
        ghidra_headless: Path to the analyzeHeadless script
        all_functions: If True, decompile all functions. Otherwise, main+callees only.
        timeout: Maximum time in seconds for Ghidra to run.

    Returns:
        DecompilationResult with pseudo-C source code and metadata.

    Raises:
        DecompilationError: If decompilation fails.
    """
    if not os.path.isfile(binary_path):
        raise DecompilationError(f"Binary not found: {binary_path}")

    # Create temp directory for Ghidra project and output
    with tempfile.TemporaryDirectory(prefix="mutagen_ghidra_") as tmpdir:
        project_dir = os.path.join(tmpdir, "project")
        os.makedirs(project_dir, exist_ok=True)

        output_file = os.path.join(tmpdir, "decompiled_output.c")
        script_file = os.path.join(tmpdir, "MutagenExportDecompiled.java")

        # Write the Ghidra postscript
        script_content = _generate_ghidra_postscript(output_file, all_functions)
        with open(script_file, "w", encoding="utf-8") as f:
            f.write(script_content)

        # Build the analyzeHeadless command
        cmd = [
            ghidra_headless,
            project_dir,
            "MutagenTempProject",
            "-import", binary_path,
            "-scriptPath", tmpdir,
            "-postScript", "MutagenExportDecompiled.java",
            "-deleteProject",
            "-scriptlog", os.path.join(tmpdir, "script.log"),
        ]

        console.print(f"[dim]  Invoking Ghidra headless analyzer...[/dim]")
        console.print(f"[dim]  Command: {' '.join(os.path.basename(c) for c in cmd[:3])} ...[/dim]")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir,
            )
        except subprocess.TimeoutExpired:
            raise DecompilationError(
                f"Ghidra timed out after {timeout}s. The binary may be too large.\n"
                f"Try increasing the timeout or using --decompile-all=false."
            )
        except FileNotFoundError:
            raise DecompilationError(
                f"Could not execute Ghidra at: {ghidra_headless}\n"
                f"Ensure Java (JDK 17+) is installed and JAVA_HOME is set."
            )

        if result.returncode != 0 and not os.path.exists(output_file):
            stderr_excerpt = (result.stderr or "")[:500]
            raise DecompilationError(
                f"Ghidra decompilation failed (exit code {result.returncode}).\n"
                f"Stderr: {stderr_excerpt}"
            )

        # Read the decompiled output
        if not os.path.exists(output_file):
            raise DecompilationError(
                "Ghidra completed but produced no output.\n"
                "The binary may not contain recognizable code."
            )

        with open(output_file, "r", encoding="utf-8", errors="replace") as f:
            pseudo_source = f.read()

        if not pseudo_source.strip():
            raise DecompilationError(
                "Ghidra produced empty decompilation output.\n"
                "The binary may be packed, obfuscated, or contain no executable code."
            )

        # Parse metadata from the decompiled output
        architecture = "unknown"
        binary_format = "unknown"
        functions_found = 0

        for line in pseudo_source.splitlines():
            if "// Architecture:" in line:
                architecture = line.split(":", 1)[1].strip()
            elif "// Format:" in line:
                binary_format = line.split(":", 1)[1].strip()
            elif "// --- Total functions decompiled:" in line:
                try:
                    functions_found = int(line.split(":")[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass

        return DecompilationResult(
            pseudo_source=pseudo_source,
            functions_found=functions_found,
            architecture=architecture,
            binary_format=binary_format,
            binary_path=binary_path,
            decompiler_used="ghidra",
        )
