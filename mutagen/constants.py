"""
Mutagen Runtime Constants
=========================
Single source of truth for every tunable default in the Mutagen pipeline.

Every constant here can be overridden via the corresponding environment
variable so that production deployments, CI grids, and local developer
environments never need to touch source code.

Usage::

    from mutagen.constants import DEFAULT_MODEL_GEMINI, DEFAULT_EXEC_TIMEOUT
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# LLM Provider & Model Defaults
# ---------------------------------------------------------------------------

#: Default AI provider ("gemini", "openai", "claude", "ollama").
DEFAULT_PROVIDER: str = os.environ.get("MUTAGEN_PROVIDER", "gemini")

#: Default Gemini model name when no --model flag is given.
DEFAULT_MODEL_GEMINI: str = os.environ.get("MUTAGEN_MODEL", "gemini-2.5-flash")

# ---------------------------------------------------------------------------
# Execution / Fuzzing Defaults
# ---------------------------------------------------------------------------

#: Per-payload subprocess execution timeout (seconds).
DEFAULT_EXEC_TIMEOUT: int = int(os.environ.get("MUTAGEN_EXEC_TIMEOUT", "5"))

#: Maximum number of self-healing patch-then-verify iterations.
DEFAULT_MAX_PATCH_RETRIES: int = int(os.environ.get("MUTAGEN_MAX_PATCH_RETRIES", "3"))

# ---------------------------------------------------------------------------
# Docker Sandbox Resource Limits
# ---------------------------------------------------------------------------

#: Memory cap for the Docker sandbox container (e.g. "512m", "1g").
DOCKER_MEMORY_LIMIT: str = os.environ.get("MUTAGEN_DOCKER_MEMORY", "512m")

#: CPU quota for the Docker sandbox container (e.g. "1.0", "2.0").
DOCKER_CPU_LIMIT: str = os.environ.get("MUTAGEN_DOCKER_CPUS", "1.0")

# ---------------------------------------------------------------------------
# Gemini API / httpx Transport Timeouts
# ---------------------------------------------------------------------------

#: Total httpx request timeout for Gemini API calls (seconds).
GEMINI_HTTP_TIMEOUT: float = float(os.environ.get("MUTAGEN_GEMINI_HTTP_TIMEOUT", "15.0"))

#: TCP connect timeout for Gemini API calls (seconds).
GEMINI_HTTP_CONNECT_TIMEOUT: float = float(os.environ.get("MUTAGEN_GEMINI_CONNECT_TIMEOUT", "5.0"))

#: Read timeout for Gemini API calls (seconds).
GEMINI_HTTP_READ_TIMEOUT: float = float(os.environ.get("MUTAGEN_GEMINI_READ_TIMEOUT", "10.0"))

#: Write timeout for Gemini API calls (seconds).
GEMINI_HTTP_WRITE_TIMEOUT: float = float(os.environ.get("MUTAGEN_GEMINI_WRITE_TIMEOUT", "10.0"))

#: Seconds to sleep when a 429 / RESOURCE_EXHAUSTED rate-limit is hit.
GEMINI_RATE_LIMIT_WAIT: int = int(os.environ.get("MUTAGEN_RATE_LIMIT_WAIT", "20"))

# ---------------------------------------------------------------------------
# LLM Generation Parameters
# ---------------------------------------------------------------------------

#: Sampling temperature for the TriageAgent (lower = more deterministic).
TRIAGE_TEMPERATURE: float = float(os.environ.get("MUTAGEN_TRIAGE_TEMPERATURE", "0.1"))

#: Sampling temperature for the PayloadSynthesizerAgent (higher = more creative).
SYNTHESIZER_TEMPERATURE: float = float(os.environ.get("MUTAGEN_SYNTHESIZER_TEMPERATURE", "0.5"))

# ---------------------------------------------------------------------------
# Compiler Discovery (Windows)
# ---------------------------------------------------------------------------

#: Ordered list of GCC binary paths to probe on Windows before falling back
#: to the system PATH. Extend via the MUTAGEN_GCC_PATH env var.
GCC_CANDIDATES_WINDOWS: list[str] = [
    p for p in [
        os.environ.get("MUTAGEN_GCC_PATH", ""),  # Explicit override first
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
        r"C:\msys64\mingw32\bin\gcc.exe",
        r"C:\MinGW\bin\gcc.exe",
        r"C:\TDM-GCC-64\bin\gcc.exe",
        "gcc",   # Fall back to PATH
    ]
    if p  # Drop the empty string if MUTAGEN_GCC_PATH is not set
]
