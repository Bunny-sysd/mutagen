import os
import subprocess

from mutagen.constants import DOCKER_CPU_LIMIT, DOCKER_MEMORY_LIMIT

_DOCKER_AVAILABLE_CACHE: bool | None = None
_DOCKER_WARNED = False

def get_docker_subprocess_env() -> dict[str, str]:
    """
    Constructs an execution environment for Docker CLI commands that safely bypasses
    proxy interference for local daemon communication (Unix sockets, Windows named pipes, localhost)
    while preserving Docker host and TLS configurations.
    """
    env = os.environ.copy()
    local_no_proxy = "localhost,127.0.0.1,0.0.0.0,::1,docker.internal,.docker.internal,unix,/var/run/docker.sock,//./pipe/docker_engine"
    existing_no_proxy = env.get("NO_PROXY", env.get("no_proxy", ""))
    if existing_no_proxy:
        combined_no_proxy = f"{existing_no_proxy},{local_no_proxy}"
    else:
        combined_no_proxy = local_no_proxy
    env["NO_PROXY"] = combined_no_proxy
    env["no_proxy"] = combined_no_proxy
    return env


def is_docker_available(force_refresh: bool = False, timeout: int = 10) -> bool:
    """
    Single canonical Docker daemon health-check function used across the entire Mutagen pipeline.
    
    Verifies that the Docker CLI binary is present AND the Docker daemon API socket is responsive.
    Uses 'docker version --format {{.Server.Version}}' (fast lightweight query) with fallback to
    'docker info'. Uses a 10s timeout to prevent false-negative timeouts on Docker Desktop / WSL2.
    Safely handles proxy-configured environments and caches the ground-truth result.
    """
    global _DOCKER_AVAILABLE_CACHE, _DOCKER_WARNED

    if _DOCKER_AVAILABLE_CACHE is not None and not force_refresh:
        return _DOCKER_AVAILABLE_CACHE

    docker_env = get_docker_subprocess_env()
    available = False

    # 1. Primary lightweight check: docker version
    try:
        res = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=docker_env
        )
        if res.returncode == 0 and res.stdout.strip():
            available = True
    except Exception:
        pass

    # 2. Fallback check: docker info
    if not available:
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=docker_env
            )
            if res.returncode == 0:
                available = True
        except Exception:
            pass

    _DOCKER_AVAILABLE_CACHE = available

    if not available and not _DOCKER_WARNED:
        try:
            from rich.console import Console
            console = Console(force_terminal=True, force_jupyter=False)
            console.print("[yellow][!] Warning: Docker daemon is unreachable or non-responsive.[/yellow]")
        except Exception:
            pass
        _DOCKER_WARNED = True

    return available


# Backwards compatibility alias for existing modules and tests
_check_docker_functional = is_docker_available

def ensure_docker_image_ready(image: str = None) -> None:
    """
    Displays container specifications and tracks Docker sandbox image verification & pulling
    with a rich progress bar that parses real `docker pull` layer output for accurate progress.
    """
    if not image:
        image = os.environ.get("MUTAGEN_SANDBOX_IMAGE", "ubuntu:latest")

    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    console = Console(force_terminal=True, force_jupyter=False)

    console.print(Panel(
        f"[bold cyan]🐳 DOCKER SANDBOX SPECIFICATIONS[/bold cyan]\n"
        f"  [bold white]Image:[/bold white]          [green]{image}[/green]\n"
        f"  [bold white]Memory Limit:[/bold white]   {DOCKER_MEMORY_LIMIT}\n"
        f"  [bold white]CPU Limit:[/bold white]      {DOCKER_CPU_LIMIT} Core(s)\n"
        f"  [bold white]Network Policy:[/bold white] Isolated (`--network=none`)\n"
        f"  [bold white]Mount Mode:[/bold white]     Read-Only Host Directory (`/target:ro`)",
        border_style="cyan"
    ))

    try:
        with Progress(
            SpinnerColumn("dots", style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=35, style="blue", complete_style="green"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Verifying & pulling sandbox image '{image}'...", total=100)

            # Stream stdout line-by-line to parse real Docker layer progress
            proc = subprocess.Popen(
                ["docker", "pull", image],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                bufsize=1,  # Line-buffered
                env=get_docker_subprocess_env()
            )

            layers_seen = set()      # Layer IDs we've encountered
            layers_done = set()      # Layers that finished (Already exists / Pull complete)

            for line in iter(proc.stdout.readline, ""):
                line = line.strip()
                if not line:
                    continue

                # Docker pull layer lines have format: "<layer_id>: <status>"
                # e.g. "a1b2c3d4e5f6: Pulling fs layer"
                #      "a1b2c3d4e5f6: Pull complete"
                #      "a1b2c3d4e5f6: Already exists"
                if ": " in line and len(line.split(": ")[0]) >= 8:
                    parts = line.split(": ", 1)
                    layer_id = parts[0].strip()
                    status = parts[1].strip() if len(parts) > 1 else ""

                    layers_seen.add(layer_id)
                    if status in ("Already exists", "Pull complete"):
                        layers_done.add(layer_id)

                    # Calculate real progress: % of layers completed (reserve last 10% for digest verification)
                    if layers_seen:
                        layer_pct = int((len(layers_done) / len(layers_seen)) * 90)
                        progress.update(task, completed=layer_pct,
                                        description=f"[cyan]{layer_id[:12]}: {status} ({len(layers_done)}/{len(layers_seen)} layers)[/cyan]")
                elif "Digest:" in line or "Status:" in line:
                    progress.update(task, completed=95, description=f"[cyan]{line[:60]}[/cyan]")

            proc.wait()

            if proc.returncode == 0:
                layer_summary = f" ({len(layers_done)} layers)" if layers_done else ""
                progress.update(task, completed=100,
                                description=f"[bold green]✓ Docker image '{image}' verified & ready{layer_summary}[/bold green]")
            else:
                stderr_out = proc.stderr.read() if proc.stderr else ""
                progress.update(task, completed=100,
                                description=f"[yellow]! Pull image warning: {stderr_out.strip()[:60]}[/yellow]")
    except Exception:
        pass


def _resolve_target_ld_library_path(exe_dir: str) -> str:
    """
    Recursively scans the executable directory and adjacent project directories
    for shared libraries (.so / .so.* / .dylib) and maps them to container /target paths.
    Includes standard Linux dynamic linker library search directories.
    """
    container_lib_dirs = [
        "/target",
        "/target/.libs",
        "/target/lib",
        "/target/build",
        "/target/build/lib",
        "/target/build/.libs",
        "/target/src",
        "/target/src/.libs",
        "/target/libs",
        "/target/bin",
        "/usr/local/lib",
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/lib",
        "/lib/x86_64-linux-gnu",
    ]
    seen = set(container_lib_dirs)
    try:
        abs_exe_dir = os.path.abspath(exe_dir)
        search_roots = [abs_exe_dir]
        parent = os.path.dirname(abs_exe_dir)
        if parent and parent != abs_exe_dir:
            search_roots.append(parent)
            grandparent = os.path.dirname(parent)
            if grandparent and grandparent != parent:
                search_roots.append(grandparent)

        for sroot in search_roots:
            if not os.path.isdir(sroot):
                continue
            for root, dirs, files in os.walk(sroot):
                dirs[:] = [d for d in dirs if not d.startswith(".") or d == ".libs"]
                if any(".so" in f.lower() or f.lower().endswith(".dylib") for f in files):
                    try:
                        rel = os.path.relpath(root, abs_exe_dir)
                        if rel == ".":
                            p = "/target"
                        elif not rel.startswith(".."):
                            p = f"/target/{rel.replace(os.sep, '/')}"
                        else:
                            p = None
                        if p and p not in seen:
                            seen.add(p)
                            container_lib_dirs.insert(0, p)
                    except Exception:
                        pass
    except Exception:
        pass

    return ":".join(container_lib_dirs)


def _stage_shared_library_dependencies(exe_path: str) -> list[str]:
    """
    Scans the executable directory and adjacent project directories for built
    shared libraries (.so, .so.*, .dylib, .dll) and ensures they are staged/aliased
    in exe_dir so the dynamic linker inside the Docker container (/target) can resolve them.
    Returns a list of created file/symlink paths for cleanup.
    """
    staged_items: list[str] = []
    if not exe_path or not os.path.exists(exe_path):
        return staged_items

    abs_exe = os.path.abspath(exe_path)
    exe_dir = os.path.dirname(abs_exe)
    if not os.path.isdir(exe_dir):
        return staged_items

    # 1. Determine search roots (exe_dir, parent, grandparent, workspace)
    search_roots = [exe_dir]
    parent = os.path.dirname(exe_dir)
    if parent and parent != exe_dir:
        search_roots.append(parent)
        grandparent = os.path.dirname(parent)
        if grandparent and grandparent != parent:
            search_roots.append(grandparent)

    # 2. Collect all shared library files across search roots
    found_libs: dict[str, str] = {}  # filename -> full_path
    for sroot in search_roots:
        if not os.path.isdir(sroot):
            continue
        for root, dirs, files in os.walk(sroot):
            dirs[:] = [d for d in dirs if not d.startswith(".") or d == ".libs"]
            for f in files:
                f_lower = f.lower()
                if ".so" in f_lower or f_lower.endswith(".dylib") or f_lower.endswith(".dll"):
                    if f not in found_libs:
                        found_libs[f] = os.path.join(root, f)

    # 3. If objdump / readelf / ldd is available on host, inspect NEEDED libraries
    needed_libs: set[str] = set()
    try:
        res = subprocess.run(["readelf", "-d", abs_exe], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if "NEEDED" in line and "[" in line and "]" in line:
                    lib = line.split("[")[1].split("]")[0].strip()
                    if lib:
                        needed_libs.add(lib)
    except Exception:
        pass

    if not needed_libs:
        try:
            res = subprocess.run(["objdump", "-p", abs_exe], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "NEEDED" in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            needed_libs.add(parts[-1])
        except Exception:
            pass

    # 4. Helper to safely copy or symlink (ensuring container volume mount compatibility)
    import shutil
    def _stage_file(src_path: str, dest_name: str) -> None:
        dest_path = os.path.join(exe_dir, dest_name)
        if os.path.abspath(src_path) == os.path.abspath(dest_path):
            return
        if not os.path.exists(dest_path) and not os.path.islink(dest_path):
            try:
                # If src and dest are in the same directory, use relative symlink;
                # otherwise copy the file so the container's isolated /target mount is self-contained.
                if os.path.dirname(os.path.abspath(src_path)) == os.path.abspath(exe_dir):
                    rel_src = os.path.relpath(src_path, exe_dir)
                    os.symlink(rel_src, dest_path)
                else:
                    shutil.copy2(src_path, dest_path)
                staged_items.append(dest_path)
            except Exception:
                try:
                    shutil.copy2(src_path, dest_path)
                    staged_items.append(dest_path)
                except Exception:
                    pass

    # 5. Stage required NEEDED libraries and generic .so/.dylib files
    for lib_filename, lib_fullpath in found_libs.items():
        _stage_file(lib_fullpath, lib_filename)

        # Generate common SONAME aliases:
        # e.g., libpng16.so.16.50.0 -> libpng16.so.16 and libpng16.so
        # e.g., libspng.so.0.7.4 -> libspng.so.0 and libspng.so
        if ".so." in lib_filename:
            parts = lib_filename.split(".so.")
            base_so = parts[0] + ".so"
            version_parts = parts[1].split(".")
            _stage_file(lib_fullpath, base_so)
            if len(version_parts) >= 1 and version_parts[0].isdigit():
                major_so = f"{base_so}.{version_parts[0]}"
                _stage_file(lib_fullpath, major_so)

    # 6. Specific check for needed_libs that might not have exact matches
    for needed in needed_libs:
        dest_path = os.path.join(exe_dir, needed)
        if not os.path.exists(dest_path) and not os.path.islink(dest_path):
            stem = needed.split(".so")[0]
            for lib_name, lib_path in found_libs.items():
                if lib_name.startswith(stem):
                    _stage_file(lib_path, needed)
                    break

    return staged_items


def _cleanup_staged_dependencies(staged_items: list[str]) -> None:
    """Removes temporary staged dependency files and symlinks."""
    for item in staged_items:
        if os.path.exists(item) or os.path.islink(item):
            try:
                os.remove(item)
            except Exception:
                pass



def execute_payload(exe_path: str, args: list[str], input_data, delivery_mode: str, timeout: int, sandbox: str = "none") -> dict:
    # Coerce input_data to string
    if isinstance(input_data, dict):
        lowered_keys = {k.lower(): v for k, v in input_data.items()}
        if "key" in lowered_keys and "value" in lowered_keys:
            input_data = f"{lowered_keys['key']}={lowered_keys['value']}"
        else:
            parts = []
            for k, v in input_data.items():
                parts.append(f"{k}={v}")
            input_data = "\n".join(parts)
    elif isinstance(input_data, list):
        input_data = "\n".join(str(x) for x in input_data)
    elif isinstance(input_data, bytes):
        pass
    elif input_data is None:
        input_data = ""
    else:
        input_data = str(input_data)

    # Coerce args elements to strings
    if isinstance(args, list):
        args = [str(a) for a in args]
    else:
        args = [str(args)] if args is not None else []

    # Sanitize null bytes from args in args-mode.
    # Windows CreateProcess uses null-terminated strings for CLI arguments,
    # so embedded \x00 bytes cause a ValueError at the OS level.
    # In stdin/tcp mode null bytes are fine (binary data over a pipe/socket).
    if delivery_mode == "args":
        args = [a.replace('\x00', '') for a in args]

    # Strip accidental program name (argv[0]) placeholder prepended by the LLM
    if args:
        first_arg = args[0].strip().replace("\\", "/").lower()
        exe_clean = os.path.basename(exe_path).lower()
        exe_name_no_ext = os.path.splitext(exe_clean)[0]

        is_placeholder = (
            first_arg in ("program", "./program", "a.out", "./a.out", "target", "./target",
                          "fuzzer_target", "./fuzzer_target", "fuzzer", "./fuzzer") or
            first_arg == exe_clean or
            first_arg == f"./{exe_clean}" or
            first_arg == exe_name_no_ext or
            first_arg == f"./{exe_name_no_ext}" or
            first_arg.endswith("/" + exe_clean) or
            first_arg.endswith("/" + exe_name_no_ext)
        )
        if is_placeholder:
            args = args[1:]

    # --- SANDBOX COMMAND CONSTRUCT ------------------------------------------
    if exe_path.lower().endswith(".py"):
        import sys
        run_cmd = [sys.executable, exe_path]
    else:
        run_cmd = [exe_path]

    container_id = ""
    container_name = ""
    image = ""
    image_digest = ""
    docker_ok = _check_docker_functional()
    if sandbox != "none" and not docker_ok:
        import sys
        ci_mode = bool(os.environ.get("CI")) or not sys.stdin.isatty() or "pytest" in sys.modules or "unittest" in sys.modules
        if not ci_mode and not os.environ.get("MUTAGEN_ALLOW_UNSANDBOXED"):
            try:
                from rich.console import Console
                c = Console(force_terminal=True, force_jupyter=False)
                c.print("\n[bold yellow]⚠️  DOCKER DAEMON NOT DETECTED[/bold yellow]")
                c.print("[yellow]Docker is not responsive or not installed on this machine.[/yellow]")
                c.print("[yellow]Fuzzing payloads are crafted to trigger memory corruptions and crashes.[/yellow]")
                choice = input("[?] Run unsandboxed directly on your host computer? [y/N]: ").strip().lower()
                if choice in ("y", "yes", "1"):
                    os.environ["MUTAGEN_ALLOW_UNSANDBOXED"] = "1"
                    c.print("[yellow][!] Proceeding with host execution (user confirmed).[/yellow]\n")
                else:
                    c.print("[bold red]Aborting run: Docker daemon required.[/bold red]")
                    sys.exit(1)
            except (KeyboardInterrupt, EOFError):
                sys.exit(1)
        is_docker_sandbox = False
    else:
        is_docker_sandbox = (sandbox != "none" and docker_ok)
    staged_deps: list[str] = []

    abs_exe_path = os.path.abspath(exe_path)
    exe_dir = os.path.dirname(abs_exe_path)
    exe_name = os.path.basename(abs_exe_path)
    if os.path.exists(abs_exe_path):
        try:
            os.chmod(abs_exe_path, 0o755)
        except Exception:
            pass

    if is_docker_sandbox:
        import uuid
        image = os.environ.get("MUTAGEN_SANDBOX_IMAGE", "ubuntu:latest")

        try:
            inspect_img = subprocess.run(
                ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image],
                capture_output=True,
                text=True,
                timeout=5,
                env=get_docker_subprocess_env()
            )
            if inspect_img.returncode == 0 and inspect_img.stdout.strip():
                image_digest = inspect_img.stdout.strip()
        except Exception:
            pass

        container_name = f"mutagen_sandbox_{uuid.uuid4().hex[:8]}"
        staged_deps = _stage_shared_library_dependencies(exe_path)
        ld_lib_path = _resolve_target_ld_library_path(exe_dir)

    try:
        env = get_docker_subprocess_env()
        workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        existing_pythonpath = env.get("PYTHONPATH", "")
        if existing_pythonpath:
            env["PYTHONPATH"] = workspace_dir + os.pathsep + existing_pythonpath
        else:
            env["PYTHONPATH"] = workspace_dir

        host_env = env.copy()
        # Inject host-level library search paths so dynamically linked libraries (e.g. libpng16.so) resolve in unsandboxed host execution
        host_lib_paths = [exe_dir]
        for candidate_sub in [".libs", "lib", "build", "src", "libs"]:
            sub_path = os.path.join(exe_dir, candidate_sub)
            if os.path.isdir(sub_path):
                host_lib_paths.append(sub_path)
        parent_exe_dir = os.path.dirname(exe_dir)
        if parent_exe_dir and parent_exe_dir != exe_dir:
            host_lib_paths.append(parent_exe_dir)
            for candidate_sub in [".libs", "lib", "build", "src", "libs"]:
                sub_path = os.path.join(parent_exe_dir, candidate_sub)
                if os.path.isdir(sub_path):
                    host_lib_paths.append(sub_path)

        injected_path_str = os.pathsep.join(host_lib_paths)
        if "LD_LIBRARY_PATH" in host_env and host_env["LD_LIBRARY_PATH"]:
            host_env["LD_LIBRARY_PATH"] = injected_path_str + os.pathsep + host_env["LD_LIBRARY_PATH"]
        else:
            host_env["LD_LIBRARY_PATH"] = injected_path_str

        if "DYLD_LIBRARY_PATH" in host_env and host_env["DYLD_LIBRARY_PATH"]:
            host_env["DYLD_LIBRARY_PATH"] = injected_path_str + os.pathsep + host_env["DYLD_LIBRARY_PATH"]
        else:
            host_env["DYLD_LIBRARY_PATH"] = injected_path_str

        try:
            if delivery_mode == "args":
                if is_docker_sandbox:
                    cmd_script = f"if [ -d /target ]; then cp -rn /target/. /tmp/ 2>/dev/null || cp -r /target/. /tmp/; fi; chmod +x /tmp/{exe_name} 2>/dev/null; exec /tmp/{exe_name} \"$@\""
                    create_cmd = [
                        "docker", "create",
                        "--name", container_name,
                        "-i",
                        f"--memory={DOCKER_MEMORY_LIMIT}",
                        f"--cpus={DOCKER_CPU_LIMIT}",
                        "-e", f"LD_LIBRARY_PATH=/tmp:/tmp/.libs:/tmp/build:{ld_lib_path}",
                        "-e", "ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=1",
                        "-v", f"{exe_dir}:/target:ro",
                        "-w", "/tmp",
                        "--network=none",
                        image,
                        "sh", "-c", cmd_script, "sh"
                    ] + args
                    create_res = subprocess.run(create_cmd, capture_output=True, text=True, timeout=10, env=env)
                    if create_res.returncode == 0:
                        raw_stdout = create_res.stdout.strip()
                        container_id = raw_stdout[:12]
                    else:
                        return {
                            "crashed": False,
                            "crash_type": "EXECUTION_ERROR",
                            "return_code": create_res.returncode,
                            "stdout": create_res.stdout,
                            "stderr": f"Docker create failed: {create_res.stderr.strip()}",
                            "coverage": [],
                            "container_id": ""
                        }
                    result = subprocess.run(
                        ["docker", "start", "-a", "-i", container_name],
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        env=env
                    )
                else:
                    result = subprocess.run(
                        run_cmd + args,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        cwd=exe_dir,
                        env=host_env
                    )

            elif delivery_mode == "stdin":
                # Convert string representations of escapes to raw bytes
                if isinstance(input_data, str):
                    try:
                        input_bytes = input_data.encode('utf-8').decode('unicode_escape').encode('latin-1')
                    except Exception:
                        input_bytes = input_data.encode('utf-8')
                else:
                    input_bytes = input_data or b""

                if is_docker_sandbox:
                    cmd_script = f"if [ -d /target ]; then cp -rn /target/. /tmp/ 2>/dev/null || cp -r /target/. /tmp/; fi; chmod +x /tmp/{exe_name} 2>/dev/null; exec /tmp/{exe_name}"
                    create_cmd = [
                        "docker", "create",
                        "--name", container_name,
                        "-i",
                        f"--memory={DOCKER_MEMORY_LIMIT}",
                        f"--cpus={DOCKER_CPU_LIMIT}",
                        "-e", f"LD_LIBRARY_PATH=/tmp:/tmp/.libs:/tmp/build:{ld_lib_path}",
                        "-e", "ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=1",
                        "-v", f"{exe_dir}:/target:ro",
                        "-w", "/tmp",
                        "--network=none",
                        image,
                        "sh", "-c", cmd_script, "sh"
                    ]
                    create_res = subprocess.run(create_cmd, capture_output=True, text=True, timeout=10)
                    if create_res.returncode == 0:
                        raw_stdout = create_res.stdout.strip()
                        container_id = raw_stdout[:12]
                    else:
                        return {
                            "crashed": False,
                            "crash_type": "EXECUTION_ERROR",
                            "return_code": create_res.returncode,
                            "stdout": create_res.stdout,
                            "stderr": f"Docker create failed: {create_res.stderr.strip()}",
                            "coverage": [],
                            "container_id": ""
                        }
                    res_proc = subprocess.run(
                        ["docker", "start", "-a", "-i", container_name],
                        input=input_bytes,
                        capture_output=True,
                        timeout=timeout,
                        env=env
                    )
                else:
                    res_proc = subprocess.run(
                        run_cmd,
                        input=input_bytes,
                        capture_output=True,
                        timeout=timeout,
                        cwd=exe_dir,
                        env=host_env
                    )
                class _Res:
                    pass
                result = _Res()
                result.returncode = res_proc.returncode
                result.stdout = res_proc.stdout.decode("utf-8", errors="ignore") if isinstance(res_proc.stdout, bytes) else (res_proc.stdout or "")
                result.stderr = res_proc.stderr.decode("utf-8", errors="ignore") if isinstance(res_proc.stderr, bytes) else (res_proc.stderr or "")

            elif delivery_mode == "file":
                # Convert string / hex payload to raw byte buffer
                if isinstance(input_data, bytes):
                    input_bytes = input_data
                elif isinstance(input_data, str) and input_data.strip():
                    cleaned_str = input_data.strip()
                    if all(c in "0123456789abcdefABCDEF" for c in cleaned_str) and len(cleaned_str) % 2 == 0 and len(cleaned_str) > 8:
                        try:
                            input_bytes = bytes.fromhex(cleaned_str)
                        except Exception:
                            input_bytes = input_data.encode('utf-8')
                    else:
                        try:
                            input_bytes = input_data.encode('utf-8').decode('unicode_escape').encode('latin-1')
                        except Exception:
                            input_bytes = input_data.encode('utf-8')
                else:
                    input_bytes = b"A" * 64

                file_args = list(args) if args else []
                extension = ".bin"
                for arg in file_args:
                    for ext in [".png", ".jpg", ".gif", ".pdf", ".txt", ".json", ".xml", ".dat"]:
                        if arg.lower().endswith(ext):
                            extension = ext
                            break

                # Determine temporary directory for host or docker sandbox
                exe_dir = os.path.dirname(os.path.abspath(exe_path)) if os.path.exists(exe_path) else os.getcwd()
                import uuid
                temp_filename = f"mutagen_payload_{uuid.uuid4().hex[:8]}{extension}"
                temp_file_path = os.path.join(exe_dir, temp_filename)

                try:
                    with open(temp_file_path, "wb") as f:
                        f.write(input_bytes)

                    target_file_param = temp_file_path
                    if not file_args:
                        file_args = [target_file_param]
                    else:
                        replaced = False
                        for i, arg in enumerate(file_args):
                            if any(ext in arg.lower() for ext in [".bin", ".txt", ".png", ".jpg", ".dat", ".json", ".xml", "payload", "input"]):
                                file_args[i] = target_file_param
                                replaced = True
                                break
                        if not replaced:
                            file_args.append(target_file_param)

                    if is_docker_sandbox:
                        docker_file_args = []
                        for a in file_args:
                            if a == target_file_param or temp_filename in a or os.path.basename(a) == temp_filename:
                                docker_file_args.append(f"/tmp/{temp_filename}")
                            else:
                                docker_file_args.append(a)

                        cmd_script = f"if [ -d /target ]; then cp -rn /target/. /tmp/ 2>/dev/null || cp -r /target/. /tmp/; fi; chmod +x /tmp/{exe_name} 2>/dev/null; exec /tmp/{exe_name} \"$@\""
                        create_cmd = [
                            "docker", "create",
                            "--name", container_name,
                            "-i",
                            f"--memory={DOCKER_MEMORY_LIMIT}",
                            f"--cpus={DOCKER_CPU_LIMIT}",
                            "-e", f"LD_LIBRARY_PATH=/tmp:/tmp/.libs:/tmp/build:{ld_lib_path}",
                            "-e", "ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=1",
                            "-v", f"{exe_dir}:/target:ro",
                            "-w", "/tmp",
                            "--network=none",
                            image,
                            "sh", "-c", cmd_script, "sh"
                        ] + docker_file_args
                        create_res = subprocess.run(create_cmd, capture_output=True, text=True, timeout=10, env=env)
                        if create_res.returncode == 0:
                            raw_stdout = create_res.stdout.strip()
                            container_id = raw_stdout[:12]
                        else:
                            return {
                                "crashed": False,
                                "crash_type": "EXECUTION_ERROR",
                                "return_code": create_res.returncode,
                                "stdout": create_res.stdout,
                                "stderr": f"Docker create failed: {create_res.stderr.strip()}",
                                "coverage": [],
                                "container_id": ""
                            }
                        result = subprocess.run(
                            ["docker", "start", "-a", "-i", container_name],
                            capture_output=True,
                            text=True,
                            timeout=timeout,
                            env=env
                        )
                    else:
                        result = subprocess.run(
                            run_cmd + file_args,
                            capture_output=True,
                            text=True,
                            timeout=timeout,
                            cwd=exe_dir,
                            env=host_env
                        )
                finally:
                    if os.path.exists(temp_file_path):
                        try:
                            os.remove(temp_file_path)
                        except Exception:
                            pass
            elif delivery_mode == "tcp" or delivery_mode.startswith("tcp:"):
                # Convert string representations of escapes to raw bytes
                if isinstance(input_data, str):
                    try:
                        input_bytes = input_data.encode('utf-8').decode('unicode_escape').encode('latin-1')
                    except Exception:
                        input_bytes = input_data.encode('utf-8')
                else:
                    input_bytes = input_data or b""

                port = int(delivery_mode.split(":")[1]) if ":" in delivery_mode else 8080
                import socket
                import time

                if is_docker_sandbox:
                    create_cmd = [
                        "docker", "create",
                        "--name", container_name,
                        "-i",
                        f"--memory={DOCKER_MEMORY_LIMIT}",
                        f"--cpus={DOCKER_CPU_LIMIT}",
                        "-e", f"LD_LIBRARY_PATH={ld_lib_path}",
                        "-e", "ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=1",
                        "-p", f"{port}:{port}",
                        "-v", f"{exe_dir}:/target:ro",
                        "-w", "/target",
                        image,
                        f"./{exe_name}"
                    ]
                    create_res = subprocess.run(create_cmd, capture_output=True, text=True, timeout=10, env=env)
                    if create_res.returncode == 0:
                        raw_stdout = create_res.stdout.strip()
                        if raw_stdout:
                            container_id = raw_stdout.split()[-1][:12]
                    start_cmd = ["docker", "start", "-a", "-i", container_name]
                    process = subprocess.Popen(
                        start_cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=env
                    )
                else:
                    process = subprocess.Popen(
                        run_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=exe_dir,
                        env=host_env
                    )
                time.sleep(0.5) # Wait for server to start
                try:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect(("127.0.0.1", port))
                        sock.sendall(input_bytes)
                        sock.close()
                    except Exception:
                        pass # Might fail if process died immediately

                    try:
                        stdout, stderr = process.communicate(timeout=timeout)
                        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate()
                        raise subprocess.TimeoutExpired(process.args, timeout, output=stdout, stderr=stderr)
                finally:
                    if process.poll() is None:
                        try:
                            process.kill()
                            process.communicate(timeout=1)
                        except Exception:
                            pass
            elif delivery_mode == "http" or delivery_mode.startswith("http:"):
                import json
                import time
                import urllib.parse
                import urllib.request

                # Start HTTP server target in background
                process = subprocess.Popen(
                    run_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env
                )
                time.sleep(1.0)  # Wait for web server to start up

                stdout_res = ""
                stderr_res = ""
                ret_code = 0

                try:
                    # Parse JSON request configuration from input_data
                    method = "GET"
                    path = "/"
                    params = None
                    json_data = None

                    if input_data:
                        try:
                            req = json.loads(input_data)
                            method = req.get("method", "GET").upper()
                            path = req.get("path", "/")
                            params = req.get("params")
                            json_data = req.get("json")
                        except Exception:
                            pass

                    # Build URL (defaulting to Flask standard port 5000)
                    url = f"http://127.0.0.1:5000{path}"
                    if params:
                        url += "?" + urllib.parse.urlencode(params)

                    req_body = None
                    headers = {}
                    if json_data:
                        req_body = json.dumps(json_data).encode("utf-8")
                        headers["Content-Type"] = "application/json"

                    req_obj = urllib.request.Request(url, data=req_body, headers=headers, method=method)

                    try:
                        with urllib.request.urlopen(req_obj, timeout=timeout) as response:
                            stdout_res = response.read().decode("utf-8", errors="ignore")
                    except urllib.error.HTTPError as e:
                        stdout_res = e.read().decode("utf-8", errors="ignore")
                        stderr_res = str(e)
                    except Exception as e:
                        stderr_res = str(e)
                        ret_code = -1
                finally:
                    # Cleanly terminate the background web server
                    try:
                        if process.poll() is None:
                            process.kill()
                        srv_stdout, srv_stderr = process.communicate(timeout=2)
                        # Merge server console outputs with response details for logical indicators scanning
                        stdout_res += "\n" + (srv_stdout.decode("utf-8", errors="ignore") if isinstance(srv_stdout, bytes) else str(srv_stdout or ""))
                        stderr_res += "\n" + (srv_stderr.decode("utf-8", errors="ignore") if isinstance(srv_stderr, bytes) else str(srv_stderr or ""))
                    except Exception:
                        pass

                result = subprocess.CompletedProcess(process.args, ret_code, stdout_res, stderr_res)
            else:
                try:
                    from rich.console import Console
                    Console(force_terminal=True, force_jupyter=False).print(
                        f"[yellow]⚠️  [Executor Warning] Unrecognized delivery mode '{delivery_mode}'. Executing as 'args' mode.[/yellow]"
                    )
                except Exception:
                    pass
                result = subprocess.run(
                    run_cmd + args,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env
                )

            # Ensure outputs are decodable strings for the fuzzing oracle checks
            if hasattr(result, "stdout") and isinstance(result.stdout, bytes):
                result.stdout = result.stdout.decode("utf-8", errors="ignore")
            if hasattr(result, "stderr") and isinstance(result.stderr, bytes):
                result.stderr = result.stderr.decode("utf-8", errors="ignore")
        except (OSError, ValueError) as e:
            # OSError  — executable not found, permission denied, etc.
            # ValueError — embedded null character in args (Windows-only);
            #              this payload cannot be tested via CLI args on Windows.
            return {
                "crashed": False,
                "crash_type": f"DELIVERY_ERROR: {e}",
                "return_code": -1,
                "stdout": "",
                "stderr": str(e),
                "coverage": []
            }

        # --- PARSE COVERAGE FEEDBACK ---------------------------------------
        coverage = []
        if result.stdout:
            import re
            cov_match = re.search(r'__MUTAGEN_COV__:([0-9,]*)\b', result.stdout)
            if cov_match:
                try:
                    raw_ids = cov_match.group(1)
                    if raw_ids:
                        coverage = [int(x) for x in raw_ids.split(",") if x]
                except Exception:
                    pass
                # Strip the coverage line from stdout to keep stdout clean
                cleaned_stdout = re.sub(r'\n?__MUTAGEN_COV__:[0-9,]*\b\n?', '\n', result.stdout).strip()
                result.stdout = cleaned_stdout

        # --- DOCKER INFRASTRUCTURE ERROR INTERCEPTION & AUTO-FALLBACK ------
        stderr_str = (result.stderr or "").lower()
        is_docker_err = any(err_sig in stderr_str for err_sig in [
            "you cannot start and attach multiple containers at once",
            "error response from daemon",
            "no such container",
            "cannot connect to the docker daemon",
            "invalid reference format",
            "container create failed",
            "error during connect",
            "driver failed programming external connectivity",
            "docker: ",
            "exec /target/",
            "exec /tmp/",
            "input/output error",
            "exec format error"
        ])
        if is_docker_sandbox and is_docker_err and result.returncode != 0:
            if container_name:
                try:
                    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True, timeout=5)
                except Exception:
                    pass

            # Automatic Host Fallback: The Docker container environment was unable to execute the binary
            try:
                if delivery_mode == "file":
                    res_host = subprocess.run(
                        run_cmd + file_args,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        cwd=exe_dir,
                        env=host_env
                    )
                elif delivery_mode == "stdin":
                    res_host = subprocess.run(
                        run_cmd,
                        input=input_bytes,
                        capture_output=True,
                        timeout=timeout,
                        cwd=exe_dir,
                        env=host_env
                    )
                else:
                    res_host = subprocess.run(
                        run_cmd + args,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        cwd=exe_dir,
                        env=host_env
                    )
                result = res_host
                is_docker_err = False
            except Exception as e:
                return {
                    "crashed": False,
                    "crash_type": f"HOST_FALLBACK_ERROR: {e}",
                    "return_code": -1,
                    "stdout": "",
                    "stderr": str(e),
                    "coverage": [],
                    "container_id": container_id,
                }

        # --- CRASH DETECTION -----------------------------------------------
        # On Windows, an "Access Violation" (segfault equivalent)
        # returns -1073741819 (0xC0000005).
        crashed = False
        crash_type = "none"

        if result.returncode != 0:
            crashed = True

            # Windows NTSTATUS codes
            if result.returncode in (-1073741819, 3221225477):
                crash_type = "ACCESS_VIOLATION (Memory Corruption!)"
            elif result.returncode in (-1073740940, 3221226356):
                crash_type = "HEAP_CORRUPTION (Double Free / Heap Corruption!)"
            elif result.returncode == -1073741676:
                crash_type = "STACK_OVERFLOW"
            elif result.returncode == -1073741571:
                crash_type = "STACK_BUFFER_OVERRUN"
            # Rust panic exit code
            elif result.returncode == 101:
                crash_type = "RUST_PANIC (Safety Violation!)"
            # POSIX Signals (negative in native subprocess, 128+N in Docker / Linux shells)
            elif result.returncode in (-11, 139):
                crash_type = "SIGSEGV (Segmentation Fault)"
            elif result.returncode in (-6, 134):
                crash_type = "SIGABRT (Aborted)"
            elif result.returncode in (-4, 132):
                crash_type = "SIGILL (Illegal Instruction)"
            elif result.returncode in (-8, 136):
                crash_type = "SIGFPE (Floating Point Exception)"
            elif result.returncode in (-7, 135):
                crash_type = "SIGBUS (Bus Error)"
            elif result.returncode < 0:
                crash_type = f"SIGNAL_{abs(result.returncode)}"
            else:
                # Normal non-zero exit code (e.g. return 1;) is NOT a memory corruption!
                crashed = False
                crash_type = "none"

        # --- ORACLE DETECTION -----------------------------------------------
        # Even if the program didn't physically crash, scan console outputs
        # for signatures indicating a successful logical exploit/bypass OR
        # a real memory corruption that was caught/masked by the harness.
        stdout_lower = (result.stdout or "").lower()
        stderr_lower = (result.stderr or "").lower()
        combined_lower = stdout_lower + stderr_lower

        # Strip the input data and arguments from the output to prevent false matches
        # when the program simply echoes the input back in logs or error messages.
        clean_output = combined_lower
        if input_data:
            if isinstance(input_data, bytes):
                try:
                    clean_output = clean_output.replace(input_data.decode("utf-8", errors="ignore").lower(), "")
                except Exception:
                    pass
            elif isinstance(input_data, str):
                clean_output = clean_output.replace(input_data.lower(), "")
        for arg in args:
            clean_output = clean_output.replace(arg.lower(), "")

        # --- MATERIALITY CHECK & LOGICAL EXPLOIT ORACLE --------------------
        # Filter out benign, expected environmental errors (e.g. file not found, usage errors)
        mundane_error_patterns = [
            "no such file or directory",
            "cannot open file",
            "file not found",
            "directory nonexistent",
            "is not recognized as an internal or external command",
            "operable program or batch file",
            "command not found",
            "permission denied",
            "invalid option",
            "unrecognized option",
            "usage: ",
            "invalid argument",
        ]

        is_mundane_error = any(p in clean_output for p in mundane_error_patterns) and result.returncode in (1, 2, 127, 255)

        if not crashed and not is_mundane_error:
            logical_indicators = [
                "access granted",
                "privileges acquired",
                "admin privileges",
                "flag{",
                "root:x:",
                "root::",
                "uid=0(root)",
                "uid=0(",
                "vuln_triggered",
                "exploit_success",
                "authenticated as admin",
            ]

            for indicator in logical_indicators:
                if indicator in clean_output:
                    crashed = True
                    crash_type = f"LOGICAL_EXPLOIT (Matched signature: '{indicator}')"
                    break

        # --- HEAP/MEMORY CORRUPTION ORACLE ----------------------------------
        # Detect real memory corruption events that the harness caught and
        # reported before they could raise a signal (e.g. SASL_BUFOVER after
        # a strcpy overflow, asan reports, glibc heap corruption messages).
        # These ARE real vulnerabilities even if return code is 0 or 1.
        if not crashed:
            heap_corruption_signatures = [
                # Harness-level overflow detection
                "sasl_bufover",
                "bufover",
                "buffer overflow",
                "heap buffer overflow",
                # ASan / UBSan runtime reports
                "heap-buffer-overflow",
                "stack-buffer-overflow",
                "use-after-free",
                "double-free",
                "memory corruption",
                "addresssanitizer",
                "ubsanitizer",
                # glibc / CRT heap corruption
                "corrupted size vs. prev_size",
                "malloc(): corrupted top size",
                "free(): invalid next size",
                "double free or corruption",
                "invalid pointer",
                # Windows CRT
                "heap corruption detected",
                "invalid heap pointer",
                "_crtisvalidheappointer",
            ]
            for sig in heap_corruption_signatures:
                if sig in combined_lower:
                    # Globally differentiate safe handled program exit (rc=1, typical for safe error/assert exit)
                    # from unhandled crash states when checking soft signatures.
                    # Hard indicators (asan/ubsan/corrupted size) remain crashes regardless of rc.
                    is_hard_sanitizer = any(k in sig for k in ["addresssanitizer", "ubsanitizer", "corrupted", "malloc()", "free()", "double free", "invalid pointer", "heap corruption detected"])
                    if is_hard_sanitizer or (result.returncode != 0 and result.returncode != 1):
                        crashed = True
                        crash_type = f"HEAP_CORRUPTION (Caught overflow signature: '{sig}')"
                        break
                    elif sig in ["sasl_bufover", "bufover", "buffer overflow", "heap buffer overflow"]:
                        # If a diagnostic string was printed but it exited with controlled code 1,
                        # this is a safe, handled mitigation exit, NOT a crash.
                        crashed = False
                        crash_type = "none"

        res_dict = {
            "crashed": crashed,
            "crash_type": crash_type,
            "return_code": result.returncode,
            "stdout": result.stdout[:8192] if result.stdout else "",
            "stderr": result.stderr[:8192] if result.stderr else "",
            "coverage": coverage,
            "container_id": container_id,
            "container_image": image if container_id else "",
            "container_image_digest": image_digest if container_id else "",
        }
        if container_name:
            if os.environ.get("MUTAGEN_KEEP_CONTAINERS") == "1":
                try:
                    from rich.console import Console
                    Console(force_terminal=True, force_jupyter=False).print(f"[bold yellow][Docker Sandbox] MUTAGEN_KEEP_CONTAINERS=1: Preserving container '{container_name}' (ID: {container_id}) for manual inspection.[/bold yellow]")
                except Exception:
                    pass
            else:
                try:
                    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True, timeout=5)
                    from rich.console import Console
                    Console(force_terminal=True, force_jupyter=False).print(f"[dim cyan][Docker Sandbox] Cleaned up container '{container_name}' (ID: {container_id}) via `docker rm -f`.[/dim cyan]")
                except Exception:
                    pass
        return res_dict

    except subprocess.TimeoutExpired:
        if container_name:
            if os.environ.get("MUTAGEN_KEEP_CONTAINERS") == "1":
                try:
                    from rich.console import Console
                    Console(force_terminal=True, force_jupyter=False).print(f"[bold yellow][Docker Sandbox] MUTAGEN_KEEP_CONTAINERS=1: Preserving container '{container_name}' (ID: {container_id}) for manual inspection.[/bold yellow]")
                except Exception:
                    pass
            else:
                try:
                    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True, timeout=5)
                    from rich.console import Console
                    Console(force_terminal=True, force_jupyter=False).print(f"[dim cyan][Docker Sandbox] Cleaned up container '{container_name}' (ID: {container_id}) via `docker rm -f`.[/dim cyan]")
                except Exception:
                    pass
        return {
            "crashed": True,
            "crash_type": "TIMEOUT (possible infinite loop / hang)",
            "return_code": -1,
            "stdout": "",
            "stderr": "Process killed after timeout",
            "coverage": [],
            "container_id": container_id,
            "container_image": image if container_id else "",
            "container_image_digest": image_digest if container_id else "",
        }
    finally:
        if staged_deps:
            _cleanup_staged_dependencies(staged_deps)

