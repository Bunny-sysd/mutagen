# Mutagen AI Fuzzer: Future Updates & Roadmap

This file tracks completed development milestones and acts as a log for upcoming features and architectural improvements.

---

## Completed Phases

### Phase 1: Secure Containerized Sandboxing (Docker Sandbox Mode)
- **Opt-in CLI flag**: Added `--sandbox docker` to isolate targets.
- **Graceful Fallback**: Automatically degrades to host execution if Docker is offline or missing.
- **Resource Containment**: Enforces CPU (`1.0`) and RAM (`512MB`) restrictions.
- **Upfront Pulling**: Prevents execution timeout failures by pre-caching target Docker images at startup.

### Phase 2: Coverage-Guided Hybrid Fuzzing
- **Source Instrumentation**: Analyzes C/C++ target source code and injects trace callbacks (`__mutagen_cov_trace`) after executable blocks while safely skipping struct/enum declarations and array initializers.
- **Stdout Trace Channel**: Communicates basic block IDs to the executor via standard out using `__MUTAGEN_COV__:` markers.
- **Python Mutation Engine**: Mutates seed inputs using bit-flipping, arithmetic operations, boundary character insertions, and string truncations.
- **Feedback Loop**: Seeds that hit new code blocks are queued for mutation, combining coverage-guided exploration with AI reasoning.

### Phase 3: Official GitHub Action Integration
- **Multi-language CI Reports**: Upgraded `ci_helper.py` to parse and build HTML/Markdown summaries for all supported extensions (.rs, .go, .java, .cs, .c, .cpp).
- **Auto-Commit Integration**: Automatically commits and pushes verified patches back to the PR branch.
- **CI Security Boundaries**: Excluded untrusted binary execution inside pull requests to prevent runner hijacking.

---

## Future Roadmap (Next Upgrades)

### Idea 4: Real-time Interactive Web Dashboard
- **Goal**: Create a local dashboard showing real-time statistics, control flow graphs, and side-by-side patch diff editors.
- **Tech Stack**: FastAPI backend + React/Vite frontend.
- **Features**:
  - Live execution charts (execs/sec, crash count, coverage growth).
  - Side-by-side code diffs comparing original target vs auto-generated AI patches.
  - Manual exploit testing trigger console.

### Idea 5: Multi-Decompiler Support
- **Goal**: Allow users to swap Ghidra with other headless decompilers depending on local setups.
- **Engines**: Add pluggable options for Binary Ninja (headless) and Radare2 / Cutter.

### Webhook Security Upgrades
- **Authentication**: Add `--webhook-header` options to support API keys (e.g., `Authorization: Bearer <token>`).
- **Spoofing Protection**: Support HMAC signatures (e.g., `X-Mutagen-Signature`) generated with a shared secret to allow target servers to mathematically verify reports.



thinking about tools such as heretic and headroom and a smart way of integrating this into our pipeline based on user preferences. 

---

## 🔍 Exhaustive Codebase Audit & Resolution Log

This section tracks line-by-line architectural and runtime issues discovered across all Mutagen modules, along with their resolution status.

### Audit Progress Matrix
- [x] `mutagen/compiler.py` (Compilation & Multi-File Build Engine)
- [x] `mutagen/executor.py` (Payload Execution & Sandbox Isolation)
- [x] `mutagen/cli.py` (CLI Flag Parsing & Governance)
- [x] `mutagen/orchestrator.py` (Multi-Agent Swarm Orchestration)
- [x] `mutagen/decompiler.py` & `mutagen/ghidra_decompiler.py`
- [x] `mutagen/core.py` (Main Fuzzing Pipeline & Retry Loops)
- [x] `mutagen/agents/` (Triage, Synthesizer, Supervisor, Patch, Validator)
- [x] `mutagen/engines/` (Gemini, Claude, OpenAI, Ollama)
- [x] `mutagen/instrumenter.py` & `mutagen/dependency_resolver.py`
- [x] `mutagen/reporter.py`, `mutagen/poc_finder.py`, `mutagen/symbolic_solver.py`
- [x] `mutagen/static_analyzer.py` & `mutagen/ast_validator.py`

---

### Discovered Issues & Resolution Status

#### `mutagen/compiler.py`
- `[BUG-01]` `[HIGH]` **Go compilation binary mismatch**: `ext == ".go"` uses `compile_args = [gcc_path, "build", ...]` which invokes `gcc build` if `--compiler gcc` (the CLI default) is passed.
  - *Fix*: Detect if `gcc_path` is `"gcc"` or not a Go binary, and fallback to `go` executable for `.go` files. `[RESOLVED]`
- `[BUG-02]` `[MEDIUM]` **Brittle regex for main/fuzzer detection in sibling C files**: `if "int main(" not in sib_content...` fails to match whitespace variations like `int main (` or `int\nmain(` and falsely excludes helper files that mention `LLVMFuzzerTestOneInput` in comments.
  - *Fix*: Use regex pattern `r'\b(int|void)\s+main\s*\('` and `r'\bLLVMFuzzerTestOneInput\s*\('` to accurately detect symbol definitions. `[RESOLVED]`

#### `mutagen/executor.py`
- `[BUG-03]` `[HIGH]` **`subprocess.run` text/bytes conflict in stdin delivery mode**: `subprocess.run(run_cmd, input=input_bytes, capture_output=True, text=True)` passes raw `input_bytes` (`bytes`) while setting `text=True`. In Python, passing `bytes` with `text=True` raises `TypeError` or decoding failures.
  - *Fix*: Omit `text=True` when passing `bytes` to `input`, then decode `stdout`/`stderr` safely afterward. `[RESOLVED]`
- `[BUG-04]` `[HIGH]` **Silent host execution fallback when sandbox requested**: If `--sandbox docker` is specified but Docker daemon is offline, `_check_docker_functional()` prints a warning and silently falls back to running untrusted binaries directly on host.
  - *Fix*: Enforce container isolation governance and clear warning when sandboxing is enabled. `[RESOLVED]`

#### `mutagen/cli.py`
- `[FEAT-01]` `[HIGH]` **Docker sandbox governance & `--no-sandbox` opt-out**: Make Docker container isolation default for target binary execution, add `--no-sandbox` explicit flag for opt-out, and fail hard if Docker is unavailable when sandboxing is active.
  - *Fix*: Add `--no-sandbox` explicit flag for opt-out and update CLI flag parsing. `[RESOLVED]`

#### `mutagen/orchestrator.py`
- `[BUG-05]` `[HIGH]` **Flawed language detection for non-C files**: `language="c" if target_path.endswith(".c") else "python"` defaults all `.cpp`, `.rs`, `.go`, `.java`, `.cs` files to `"python"`, causing agent prompts to select Python instructions for compiled multi-language targets.
  - *Fix*: Implement full language lookup matching `.cpp`/`.cxx` → `c++`, `.rs` → `rust`, `.go` → `go`, `.java` → `java`, `.cs` → `csharp`, `.py` → `python`, `.c` → `c`. `[RESOLVED]`

#### `mutagen/decompiler.py` & `mutagen/ghidra_decompiler.py`
- `[BUG-06]` `[MEDIUM]` **Java string escape vulnerability in `_generate_ghidra_postscript`**: `String outputPath = "{output_file.replace(os.sep, '/')}"` fails when Windows user paths contain backslashes or spaces.
  - *Fix*: Escape backslashes as `\\\\` and double-quotes as `\\"` in Java string literal template in `decompiler.py`. `[RESOLVED]`
- `[REFACTOR-01]` `[LOW]` **Orphaned prototype module `ghidra_decompiler.py`**: `ghidra_decompiler.py` is an un-imported legacy file superseded by `decompiler.py`.
  - *Fix*: Re-export `decompile_binary` and bridge `ghidra_decompiler.py` to `decompiler.py` for backward compatibility. `[RESOLVED]`

#### `mutagen/core.py`
- `[BUG-07]` `[HIGH]` **Missing `file` delivery mode branch in `verify_and_fallback_exploit`**: `verify_and_fallback_exploit` handled `args`, `stdin`, and `tcp:`, but had no branch for `file` mode, causing auto-generated Python PoC scripts for file targets to be empty.
  - *Fix*: Add explicit `elif delivery_mode == "file":` block to `verify_and_fallback_exploit()` that writes the payload to a temp file and executes the binary with the file path argument. `[RESOLVED]`
- `[BUG-08]` `[MEDIUM]` **Potential `UnicodeDecodeError` in Defects4C source open**: `open(target_src_path, encoding="utf-8")` crashes if the benchmark source contains non-UTF8 binary comments or multibyte sequences.
  - *Fix*: Pass `errors="ignore"` to `open()` when reading target source code. `[RESOLVED]`

#### `mutagen/agents/`
- `[BUG-09]` `[HIGH]` **Hardcoded delivery mode in multi-provider fallback in `triage.py`**: `triage.py` hardcoded `data = {"vulnerabilities": vuln_items, "suggested_delivery_mode": "args"}` for OpenAI/Claude/Ollama, overriding dynamic delivery classification.
  - *Fix*: Extract delivery mode from response schema or heuristics in multi-provider fallback. `[RESOLVED]`
- `[BUG-10]` `[MEDIUM]` **Missing binary payload representation in `patcher.py`**: `crash_data["input_data"]` was empty when `raw_bytes_hex` was used, depriving the LLM patch generator of crash payload details.
  - *Fix*: Include `raw_bytes_hex` and byte length in `crash_data` passed to `generate_patch()`. `[RESOLVED]`

#### `mutagen/engines/`
- `[BUG-11]` `[MEDIUM]` **Missing `raw_bytes_hex` in `refine_payload` prompts**: LLM engine refine prompts omitted `raw_bytes_hex` instructions, preventing payload refinement from outputting binary hex payloads.
  - *Fix*: Add `raw_bytes_hex` optional field instruction to refine prompts in Gemini, OpenAI, Claude, and Ollama engines. `[RESOLVED]`

#### `mutagen/instrumenter.py` & `mutagen/dependency_resolver.py`
- `[BUG-12]` `[HIGH]` **`re.DOTALL` flag swallowing source code in `instrumenter.py` comment stripper**: `flags=re.MULTILINE | re.DOTALL` caused `//.*?$` line comment regex to swallow all remaining code lines to the end of the file.
  - *Fix*: Separate block comment matching (`/\*.*?\*/`) from line comment matching (`//[^\r\n]*`) without `re.DOTALL`. `[RESOLVED]`
- `[BUG-13]` `[MEDIUM]` **`NotADirectoryError` guard in `dependency_resolver.py`**: `os.listdir(target_dir)` crashed if `target_dir` was a file or invalid directory path.
  - *Fix*: Add `if not os.path.isdir(target_dir): return None` guard to `detect_build_system()`. `[RESOLVED]`

#### `mutagen/reporter.py`
- `[BUG-14]` `[HIGH]` **Unescaped target path in report filename**: `json_file = f"crashes/crash_report_{target_name}_{timestamp}.json"` crashed with `FileNotFoundError` when `target_name` contained path separators (e.g. `../libspng/examples/example.c`).
  - *Fix*: Sanitize `target_name` into a safe filename using `os.path.basename` and replacing path separators with underscores. `[RESOLVED]`

#### `mutagen/executor.py` & `mutagen/dependency_resolver.py`
- `[BUG-15]` `[HIGH]` **Docker sandbox shared library resolution failure**: Dynamically linked binaries (e.g. `pngimage`, `pngtest`, `libspng`, `libxml2`) failed at runtime inside Docker sandbox with `error while loading shared libraries: libpng16.so.16: cannot open shared object file`.
  - *Fix*:
    1. Implemented `_stage_shared_library_dependencies()` in `executor.py` to scan project build roots, stage `.so` dependencies, and auto-create SONAME aliases (e.g. `libpng16.so.16`) directly in `exe_dir` with automatic post-execution teardown.
    2. Updated `_resolve_target_ld_library_path()` to remove literal `:$LD_LIBRARY_PATH` and provide standard glibc search paths.
    3. Added `-DBUILD_SHARED_LIBS=OFF` static linking preference with automatic dynamic fallback in `dependency_resolver.py` CMake builds. `[RESOLVED]`










