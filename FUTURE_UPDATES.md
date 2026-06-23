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