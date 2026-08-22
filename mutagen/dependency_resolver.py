import os
import re
import subprocess

from rich.console import Console

console = Console(force_terminal=True, force_jupyter=False)

SHARED_LIB_PATTERN = re.compile(r"\.(so|dylib)(\.\d+)*$|\.(dll|a|lib|o|obj|cmake|txt|ninja|d|rlib|awk|sh|py|pl|m4|in|am|h|hpp|c|cpp|cc|cxx|log|status|check|make)$", re.IGNORECASE)

def _is_shared_library_or_build_artifact(filename: str) -> bool:
    """Returns True if the filename represents a shared library, archive, script, or non-executable build artifact."""
    return bool(SHARED_LIB_PATTERN.search(filename))

# Common C/C++ header to library flag mapping
COMMON_HEADER_LIB_MAP = {
    "curl/curl.h": ["-lcurl"],
    "openssl/ssl.h": ["-lssl", "-lcrypto"],
    "openssl/crypto.h": ["-lcrypto"],
    "zlib.h": ["-lz"],
    "sqlite3.h": ["-lsqlite3"],
    "json-c/json.h": ["-ljson-c"],
    "png.h": ["-lpng"],
    "jpeg.h": ["-ljpeg"],
    "pthread.h": ["-pthread"],
    "math.h": ["-lm"],
    "dlfcn.h": ["-ldl"],
    "xml2/libxml/parser.h": ["-lxml2"],
    "ft2build.h": ["-lfreetype"],
    "uv.h": ["-luv"],
}

def detect_build_system(target_dir: str) -> str | None:
    """Detects if a project uses a standard build system (CMake, Make, Cargo, Go, .NET, Maven)."""
    if not target_dir or not os.path.isdir(target_dir):
        return None
    if os.path.exists(os.path.join(target_dir, "CMakeLists.txt")):
        return "cmake"
    if os.path.exists(os.path.join(target_dir, "Makefile")) or os.path.exists(os.path.join(target_dir, "makefile")):
        return "make"
    if os.path.exists(os.path.join(target_dir, "Cargo.toml")):
        return "cargo"
    if os.path.exists(os.path.join(target_dir, "go.mod")):
        return "go"
    if os.path.exists(os.path.join(target_dir, "pom.xml")):
        return "maven"
    for file in os.listdir(target_dir):
        if file.endswith(".csproj"):
            return "dotnet"
    return None

def _select_best_binary(candidates: list[str], target_hint: str = "") -> str | None:
    """Selects the best executable candidate from build artifacts based on target name heuristics."""
    # Exclude CMake internal artifacts and probe binaries
    filtered = []
    for cand in candidates:
        norm_path = cand.replace("\\", "/").lower()
        if any(ignored in norm_path for ignored in ["/cmakefiles/", "/cmaketmp/", "compileridc", "compileridcxx"]):
            continue
        filtered.append(cand)

    if not filtered:
        filtered = candidates

    if not filtered:
        return None
    if len(filtered) == 1:
        return filtered[0]

    hint_stem = ""
    if target_hint:
        hint_stem = os.path.splitext(os.path.basename(target_hint))[0].lower()

    scored = []
    for cand in filtered:
        cand_name = os.path.splitext(os.path.basename(cand))[0].lower()
        score = 0
        if hint_stem:
            if cand_name == hint_stem:
                score += 100
            elif hint_stem in cand_name or cand_name in hint_stem:
                score += 50
        if "test" in cand_name and "valid" not in cand_name:
            score += 20
        elif "valid" in cand_name or "check" in cand_name:
            score -= 20
        scored.append((score, cand))

    scored.sort(key=lambda x: x[0], reverse=True)
    selected = scored[0][1]
    if len(filtered) > 1:
        console.print(f"[cyan]  [Target Selection] Found {len(filtered)} candidate binaries: {[os.path.basename(c) for c in filtered]}. Selected best target: '{os.path.basename(selected)}'[/cyan]")
    return selected

def build_with_native_tool(build_system: str, target_dir: str, target_hint: str = "", vuln_function: str = None) -> str | None:
    """Invokes native build tools to build a project and returns the output binary path if successful."""
    console.print(f"[cyan]  [+] Native build system detected: '{build_system}'. Building project...[/cyan]")
    env = os.environ.copy()

    try:
        candidates = []
        if build_system == "cmake":
            build_dir = os.path.join(target_dir, "build")
            cmake_static_flags = [
                "-DCMAKE_BUILD_RPATH_USE_ORIGIN=ON",
                "-DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON",
                "-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON",
                "-DBUILD_SHARED_LIBS=OFF",
                "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            ]
            try:
                subprocess.run(["cmake", "-B", build_dir, "-S", target_dir] + cmake_static_flags, capture_output=True, text=True, check=True, cwd=target_dir, env=env)
                subprocess.run(["cmake", "--build", build_dir], capture_output=True, text=True, check=True, cwd=target_dir, env=env)
            except Exception:
                cmake_dyn_flags = [
                    "-DCMAKE_BUILD_RPATH_USE_ORIGIN=ON",
                    "-DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON",
                    "-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON",
                ]
                subprocess.run(["cmake", "-B", build_dir, "-S", target_dir] + cmake_dyn_flags, capture_output=True, text=True, check=True, cwd=target_dir, env=env)
                subprocess.run(["cmake", "--build", build_dir], capture_output=True, text=True, check=True, cwd=target_dir, env=env)

            for root, dirs, files in os.walk(build_dir):
                # Skip internal CMake directories during traversal
                dirs[:] = [d for d in dirs if d.lower() not in ("cmakefiles", "cmaketmp", "testing")]
                for f in files:
                    if not _is_shared_library_or_build_artifact(f):
                        path = os.path.join(root, f)
                        if os.access(path, os.X_OK) or f.endswith(".exe"):
                            candidates.append(path)
            from mutagen.reachability_checker import select_best_reachable_binary
            selected, status = select_best_reachable_binary(candidates, target_hint, vuln_function)
            return selected

        elif build_system == "make":
            subprocess.run(["make"], capture_output=True, text=True, check=True, cwd=target_dir, env=env)
            for f in os.listdir(target_dir):
                path = os.path.join(target_dir, f)
                if os.path.isfile(path) and (os.access(path, os.X_OK) or f.endswith(".exe")) and not f.endswith((".c", ".cpp", ".o", ".h", ".md")):
                    candidates.append(path)
            from mutagen.reachability_checker import select_best_reachable_binary
            selected, status = select_best_reachable_binary(candidates, target_hint, vuln_function)
            return selected

        elif build_system == "cargo":
            subprocess.run(["cargo", "build"], capture_output=True, text=True, check=True, cwd=target_dir, env=env)
            target_out = os.path.join(target_dir, "target", "debug")
            if os.path.exists(target_out):
                for f in os.listdir(target_out):
                    path = os.path.join(target_out, f)
                    if os.path.isfile(path) and (os.access(path, os.X_OK) or f.endswith(".exe")) and not f.endswith((".d", ".rlib")):
                        candidates.append(path)
            return _select_best_binary(candidates, target_hint)

        elif build_system == "go":
            out_bin = os.path.join(target_dir, "app.exe" if os.name == 'nt' else "app.out")
            subprocess.run(["go", "build", "-o", out_bin], capture_output=True, text=True, check=True, cwd=target_dir, env=env)
            return out_bin

        elif build_system == "dotnet":
            subprocess.run(["dotnet", "build"], capture_output=True, text=True, check=True, cwd=target_dir, env=env)
            bin_dir = os.path.join(target_dir, "bin")
            if os.path.exists(bin_dir):
                for root, _, files in os.walk(bin_dir):
                    for f in files:
                        if f.endswith(".exe") or (os.access(os.path.join(root, f), os.X_OK) and not f.endswith((".dll", ".json"))):
                            candidates.append(os.path.join(root, f))
            return _select_best_binary(candidates, target_hint)
    except Exception as e:
        console.print(f"[yellow]  [!] Native build system '{build_system}' failed or missing: {e}. Falling back to direct compilation.[/yellow]")

    return None

def get_pkgconfig_flags(package_name: str) -> list[str]:
    """Queries pkg-config for compiler/linker flags of an installed library."""
    try:
        res = subprocess.run(["pkg-config", "--cflags", "--libs", package_name], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().split()
    except Exception:
        pass
    return []

def resolve_header_dependencies(source_path: str) -> list[str]:
    """Scans source code for include directives and returns required compiler/linker flags."""
    flags = set()
    if not os.path.exists(source_path):
        return list(flags)

    try:
        with open(source_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        includes = re.findall(r'#include\s*[<"]([^>"]+)[>"]', content)
        for inc in includes:
            inc_clean = inc.strip().lower()
            if inc_clean in COMMON_HEADER_LIB_MAP:
                for flag in COMMON_HEADER_LIB_MAP[inc_clean]:
                    flags.add(flag)
            # Try pkg-config for library headers (e.g. libxml2 -> xml2)
            lib_base = inc_clean.split("/")[0].replace(".h", "")
            pkg_flags = get_pkgconfig_flags(lib_base)
            for pf in pkg_flags:
                flags.add(pf)
    except Exception:
        pass

    return sorted(list(flags))

def parse_compilation_error(stderr_output: str) -> list[str]:
    """Parses compiler stderr output to identify missing header directories or library flags for self-healing retries."""
    suggested_flags = set()

    # 1. Missing headers: fatal error: foo.h: No such file or directory
    missing_headers = re.findall(r'fatal error:\s*([^\s:]+\.h):\s*No such file or directory', stderr_output, re.IGNORECASE)
    for mh in missing_headers:
        header_name = os.path.basename(mh).lower()
        for known_header, lib_flags in COMMON_HEADER_LIB_MAP.items():
            if header_name in known_header:
                for flag in lib_flags:
                    suggested_flags.add(flag)

    # 2. Undefined references: undefined reference to `curl_easy_init` or symbol 'pow@@GLIBC_2.29'
    undefined_refs = re.findall(r'undefined reference to [`\'\s]+([^`\'\s]+)', stderr_output, re.IGNORECASE)
    for ref in undefined_refs:
        ref_lower = ref.lower()
        if "curl_" in ref_lower:
            suggested_flags.add("-lcurl")
        elif "ssl_" in ref_lower or "tls_" in ref_lower:
            suggested_flags.add("-lssl")
            suggested_flags.add("-lcrypto")
        elif "zlib" in ref_lower or "deflate" in ref_lower or "inflate" in ref_lower:
            suggested_flags.add("-lz")
        elif "sqlite3_" in ref_lower:
            suggested_flags.add("-lsqlite3")
        elif "pthread_" in ref_lower:
            suggested_flags.add("-pthread")
        elif "pow" in ref_lower or "sqrt" in ref_lower or "sin" in ref_lower or "cos" in ref_lower or "floor" in ref_lower or "ceil" in ref_lower:
            suggested_flags.add("-lm")

    # 3. DSO missing / libm symbol resolution errors
    if "dso missing" in stderr_output.lower() or "libm.so" in stderr_output.lower():
        suggested_flags.add("-lm")

    return sorted(list(suggested_flags))
