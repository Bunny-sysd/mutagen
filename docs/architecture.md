# Architecture

## Overview

Mutagen is structured as a pipeline of five phases, each handled by a dedicated module:

```
┌──────────────────────────────────────────────────────────────────┐
│                         mutagen/cli.py                          │
│                    (CLI argument parsing)                        │
└──────────────────────┬───────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                        mutagen/core.py                          │
│              (5-phase fuzzing orchestration)                     │
│                                                                  │
│  Phase 1: AI Analysis ──► Phase 2: Compile ──► Phase 3: Fuzz    │
│                                                    │             │
│                                              ┌─────┴──────┐     │
│                                              │ Crash Found │     │
│                                              └─────┬──────┘     │
│                                                    │             │
│  Phase 5: Verify ◄── Phase 4: Patch + Exploit ◄───┘             │
└──────────┬────────────────┬──────────────┬───────────────────────┘
           │                │              │
           ▼                ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
│ compiler.py  │ │ executor.py  │ │  reporter.py     │
│              │ │              │ │                    │
│ - inject     │ │ - args mode  │ │ - JSON reports    │
│   crash      │ │ - stdin mode │ │ - HTML reports    │
│   handler    │ │ - TCP mode   │ │ - XSS prevention  │
│ - compile    │ │ - crash      │ │                    │
│   target     │ │   detection  │ │                    │
└──────────────┘ └──────────────┘ └──────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────────┐
│                     mutagen/engines/                             │
│                                                                  │
│  ┌────────────┐  ┌────────────────┐  ┌─────────────┐           │
│  │ gemini.py  │  │ openai_engine  │  │  ollama.py  │           │
│  │            │  │      .py       │  │             │           │
│  │ Google     │  │ OpenAI GPT     │  │ Local LLMs  │           │
│  │ Gemini API │  │ API            │  │ (REST API)  │           │
│  └─────┬──────┘  └──────┬─────────┘  └──────┬──────┘           │
│        │                │                    │                   │
│        └────────────────┼────────────────────┘                   │
│                         │                                        │
│                    ┌────┴─────┐                                  │
│                    │ base.py  │                                  │
│                    │ (ABC)    │                                  │
│                    └──────────┘                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Module Responsibilities

### `mutagen/cli.py`
Entry point. Parses command-line arguments, resolves API keys and compiler paths, performs security checks (path traversal prevention), and launches the fuzzer.

### `mutagen/core.py`
The orchestrator. Runs the 5-phase pipeline: AI analysis → compilation → fuzzing with agentic retries → auto-patch + exploit generation → patch verification. Uses `concurrent.futures.ThreadPoolExecutor` for parallel payload execution.

### `mutagen/compiler.py`
Handles C compilation. Injects Mutagen's crash handler (Windows SEH-based) into target source code before compilation. The crash handler captures exception codes and register state (EIP/RIP) at the point of crash.

### `mutagen/executor.py`
Payload delivery and crash detection. Supports three delivery modes:
- **args**: Command-line arguments via `subprocess.run`
- **stdin**: Standard input via `subprocess.run(input=...)`
- **tcp**: TCP socket connection to network-aware targets

Crash detection maps Windows NTSTATUS codes and POSIX signals to human-readable crash types.

### `mutagen/reporter.py`
Generates crash reports in two formats:
- **JSON**: Machine-readable, suitable for CI/CD integration
- **HTML**: Beautiful glassmorphism-styled reports with animated table rows

All untrusted payload data is HTML-escaped to prevent XSS in reports.

### `mutagen/engines/`
LLM provider integrations. Each engine implements four methods:
1. `analyze_code()` — Vulnerability analysis and payload generation
2. `refine_payload()` — Agentic retry with execution feedback
3. `generate_patch()` — Secure C patch generation
4. `generate_exploit()` — Python PoC exploit generation

## Adding a New Engine

1. Create `mutagen/engines/my_engine.py`
2. Extend `LLMEngine` from `mutagen/engines/base.py`
3. Implement all four abstract methods
4. Register in `mutagen/engines/__init__.py`
5. Add to CLI choices in `mutagen/cli.py`
