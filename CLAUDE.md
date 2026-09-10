# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Mutagen is an AI-powered fuzzer and auto-patcher: it reads C/C++ (and other language) source or Ghidra-decompiled binaries, has an LLM generate targeted exploit payloads, executes them (optionally in a Docker sandbox), and on a reproduced crash runs a self-healing loop that patches the vulnerability, generates a Python PoC exploit, and re-verifies the patch. This is a defensive/educational security research tool — vulnerable `targets/*.c` files are intentional test fixtures, not real production bugs.

## Commands

```bash
# Install (editable) with dev extras
pip install -e ".[dev]"

# Run the full test suite
pytest tests/ -v

# Run a single test file / test
pytest tests/test_executor.py -v
pytest tests/test_executor.py::test_some_case -v

# Coverage
pytest tests/ -v --cov=mutagen --cov-report=term-missing

# Lint (CI runs this against mutagen/ only)
ruff check mutagen/
ruff check mutagen/ --select I --diff   # import-sort check, as run by the lint CI job

# Run the fuzzer against a target
mutagen --target targets/01_buffer_overflow.c
python -m mutagen --target targets/01_buffer_overflow.c --max-payloads 5

# Multi-agent swarm mode instead of the default linear pipeline
mutagen --target targets/22_asyn_signal_uaf.c --mode agents

# Fuzz every target in targets/ in one batch
python run_all.py --max-payloads 3
```

Tests run on Windows, Linux, and macOS in CI across Python 3.10/3.12/3.13 (`.github/workflows/ci.yml`); several tests are platform-guarded (Docker containers, macOS Java home resolution) — check for `sys.platform` / `skipif` guards before assuming a test is cross-platform.

## Architecture

### Two execution modes, one shared data path

`mutagen/core.py::run_fuzzer()` is the single entry point invoked by `cli.py`, and immediately branches on `--mode`:

- **`pipeline` (default)** — a large procedural 5-phase loop, entirely inside `core.py`: AI code analysis → compile (`compiler.py`) → agentic fuzz/execute (`executor.py`) with retry-on-failure → auto-patch + PoC exploit generation → patch verification. State is threaded through as plain args/dicts.
- **`agents`** — `mutagen/orchestrator.py::AgentOrchestrator` runs the same conceptual phases as a swarm of single-responsibility micro-agents under `mutagen/agents/` (`triage.py` → `synthesizer.py` → `supervisor.py` → `patcher.py` → `validator.py`, each a `.process(context)` async step), sharing a single Pydantic `ProgramContext` (`mutagen/state.py`) that accumulates vulnerabilities, payloads, patches, and logs as it passes between agents.

When changing shared behavior (crash detection, patch verification, delivery modes), check whether the logic lives in `core.py`, is duplicated in the matching `agents/*.py`, or has been factored out to a shared module (`executor.py`, `compiler.py`) — the two modes do not always call the same code path.

### LLM engine abstraction

`mutagen/engines/base.py::BaseEngine` defines the provider-agnostic contract (`analyze_code`, `refine_payload`, `generate_patch`, `refine_patch`, `generate_exploit`, optional `deobfuscate_code`/`generate_payloads`). Concrete engines (`gemini.py`, `claude.py`, `openai_engine.py`, `ollama.py`) implement it; `engines/__init__.py::get_engine()` selects one by `--provider`. `engines/output_parser.py` normalizes/repairs LLM JSON output shared across providers. Gemini safety thresholds are deliberately fully unblocked (`safety.py`) since this tool's normal operation is generating exploit payloads — don't "fix" that as if it were a bug.

### Sandbox / safety gating

Executing AI-generated payloads against compiled binaries is inherently destructive, so sandbox selection is a hard gate, not a preference:

- `executor.py::_check_docker_functional` / `is_docker_available` probe the Docker daemon; `ensure_docker_image_ready` provisions the sandbox image.
- In CI or any non-interactive session (`CI=1` or non-TTY), unsandboxed execution is **always** refused and the process exits 1 — this holds even if `MUTAGEN_ALLOW_UNSANDBOXED=1` or `--no-sandbox` is passed. See `AgentOrchestrator.gate_docker_sandbox_safety` and the equivalent pipeline-mode check in `core.py`.
- In an interactive TTY with no Docker daemon, the user is prompted explicitly before falling back to unsandboxed host execution.
- Path-containment checks (e.g. keeping staged/executed files inside a workspace or sandbox dir) must use `os.path.commonpath`-based segment comparison, never `str.startswith()` — and must lowercase-normalize on Windows (`os.name == 'nt'`) for case-insensitive filesystems. `executor.py::_is_system_or_root_dir` and the shared-library staging functions (`_stage_shared_library_dependencies`, `is_system_shared_library`) are the reference implementations of this pattern.

### Other structural notes

- `mutagen/state.py` Pydantic models (`VulnerabilityDetail`, `CrashPayload`, `PatchProposal`, `ProgramContext`) are the canonical schema for anything crossing an agent boundary; `mutagen/models.py` holds payload schemas used by the pipeline-mode engines.
- `mutagen/decompiler.py` + `mutagen/ghidra_decompiler.py` handle `--target *.bin/.exe --binary`: Ghidra runs headlessly to produce pseudo-C, which is fed to the same analysis path as source targets (with a note to the LLM that variable names are decompiler-generated).
- `--profile` (`legacy-audit` / `supply-chain` / `malware-triage`) changes what the triage/analysis prompt is looking for, not the execution mechanics — see how `profile` is threaded through `core.py`/`triage.py` before adding a new profile.
- `mutagen/reporter.py` produces the JSON + interactive HTML reports in `crashes/`; webhook delivery (`--webhook-url`) signs payloads with HMAC-SHA256 using `--webhook-secret`.
- `mutagen/dashboard/` is a separate optional FastAPI app (`dashboard` extra) for viewing results, distinct from the CLI/report pipeline.
- `mutagen/cve_validator.py` implements `--validate-cve`: ground-truth mode that fetches CVE metadata and gates analysis on whether the detected target version is actually affected.
- CI-specific behavior (git-diff-scoped scanning via `--ci`) lives in `mutagen/ci_helper.py`; per the CI/PR safety rule, pre-compiled binaries submitted in PRs must never be executed by the runner.
