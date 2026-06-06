# 🧬 Mutagen — AI-Powered Zero-Day Fuzzer

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.10+-green?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/AI-Gemini%20API-blue?style=for-the-badge&logo=google" />
  <img src="https://img.shields.io/badge/focus-offensive%20security-red?style=for-the-badge&logo=hackthebox" />
</p>

> **Mutagen** is an AI-powered fuzzer that reads source code, identifies vulnerabilities using Google's Gemini AI, and generates targeted payloads to crash programs — unlike traditional "dumb" fuzzers that rely on random input mutation.

---

## 🔥 Why Mutagen is Different

| Feature | Traditional Fuzzer (AFL, libFuzzer) | Mutagen |
|---|---|---|
| **Input Strategy** | Random mutations / coverage-guided | AI-analyzed, targeted payloads |
| **Code Understanding** | None (black-box) | Reads & understands source code |
| **Speed to First Crash** | Minutes to hours | Seconds |
| **Vulnerability Explanation** | None | AI explains *why* each payload works |
| **CWE Classification** | Manual | Automatic CWE IDs for each finding |
| **Reports** | Text logs | JSON + interactive HTML dashboard |
| **Multi-Arg Targets** | N/A | Handles programs with multiple arguments |
| **Setup Complexity** | High (instrumentation required) | One command |

---

## ⚡ Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/Bunny-sysd/mutagen.git
cd mutagen

# 2. Set up virtual environment
python -m venv .venv
.venv\Scripts\activate     # Windows
# source .venv/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install google-genai rich

# 4. Set your free Gemini API key (get one at https://aistudio.google.com/apikey)
$env:GEMINI_API_KEY="your-key-here"  # PowerShell
# export GEMINI_API_KEY="your-key-here"  # Bash

# 5. Run against any target!
python mutagen.py targets/01_buffer_overflow.c
python mutagen.py targets/02_format_string.c
python mutagen.py targets/03_integer_overflow.c
python mutagen.py targets/04_use_after_free.c
```

---

## 🎯 How It Works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Read .c    │────▶│  AI Analysis │────▶│  Compile &   │────▶│  Crash       │
│  Source Code│     │  (Gemini API)│     │  Fuzz Target │     │  Report      │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                           │                     │                    │
                    Generate targeted      Monitor for         JSON + HTML
                    crash payloads        segfaults &         dashboard with
                    with CWE IDs        access violations    crash analytics
```

1. **Analyze**: Mutagen reads the target C source code.
2. **AI Brain**: Sends the code to Gemini AI, which identifies vulnerabilities (buffer overflows, format strings, integer overflows, use-after-free, etc.) and generates targeted payloads with CWE classifications.
3. **Execute**: Compiles the target with protections disabled (`-fno-stack-protector`), then injects each payload.
4. **Monitor**: Watches for crashes (access violations, stack overflows, buffer overruns, timeouts).
5. **Report**: Saves crash artifacts to `crashes/` as both JSON and an interactive HTML report.

---

## 🛡️ Vulnerability Targets

Mutagen ships with 4 intentionally vulnerable programs covering the most exploited vulnerability classes in history:

| File | Vulnerability | CWE | Real-World CVEs | Difficulty |
|------|--------------|-----|-----------------|------------|
| `targets/01_buffer_overflow.c` | Stack buffer overflow via `strcpy()` | CWE-120 | CVE-2021-3156 (sudo) | 🟢 Easy |
| `targets/02_format_string.c` | Format string injection via `printf()` | CWE-134 | CVE-2012-0809 (sudo) | 🟡 Medium |
| `targets/03_integer_overflow.c` | Integer overflow → heap overflow | CWE-190 | CVE-2021-21224 (Chrome V8) | 🟠 Hard |
| `targets/04_use_after_free.c` | Use-after-free via dangling pointer | CWE-416 | CVE-2022-22620 (WebKit) | 🔴 Expert |

Each target file contains detailed comments explaining:
- What the vulnerability is and how it works
- Why the specific function/pattern is dangerous
- Real-world CVE examples where this vulnerability was exploited
- The security impact (code execution, privilege escalation, etc.)

---

## 📊 Reports

Mutagen generates two report formats:

### JSON Report (`crashes/crash_report_*.json`)
Machine-readable crash data including payloads, CWE IDs, crash types, and severity ratings.

### HTML Dashboard (`crashes/report_*.html`)
A visual dashboard you can open in any browser featuring:
- **Stats cards** — Payloads tested, crashes found, crash rate %, unique vuln types
- **Crash table** — Severity badges, CWE IDs, payload details, crash types
- **Dark theme** — Professional cybersecurity aesthetic

---

## 📂 Project Structure

```
mutagen/
├── mutagen.py                        # Main fuzzer engine (v2.0)
├── vuln.c                            # Legacy test target
├── targets/                          # Vulnerability test suite
│   ├── 01_buffer_overflow.c          # CWE-120: Stack buffer overflow
│   ├── 02_format_string.c           # CWE-134: Format string injection
│   ├── 03_integer_overflow.c        # CWE-190: Integer overflow
│   └── 04_use_after_free.c          # CWE-416: Use-after-free
├── crashes/                          # Auto-generated crash reports
│   ├── crash_report_*.json          # Machine-readable reports
│   └── report_*.html               # Visual HTML dashboards
├── .gitignore
└── README.md
```

---

## 🧠 Architecture

Mutagen is built with a modular, resilient architecture:

- **AI Engine**: Multi-model fallback system (gemini-2.5-flash → 2.0-flash → 2.0-flash-lite) with exponential backoff and rate-limit handling
- **Parser**: 3-pass resilient JSON parser that handles malformed AI responses (JSON → eval → object-by-object fallback)
- **Executor**: Multi-argument payload injection with Windows crash code detection (ACCESS_VIOLATION, STACK_OVERFLOW, STACK_BUFFER_OVERRUN)
- **Reporter**: Dual-format output (JSON + HTML) with crash analytics

---

## ⚠️ Legal Disclaimer

This tool is built for **educational and authorized security testing only**. Only use Mutagen on code you own or have explicit permission to test. Unauthorized use of fuzzing tools against systems you don't own is illegal.

---

## 🧠 Built With

- **Python 3.10+** — Core fuzzer logic
- **Google Gemini API** — AI-powered vulnerability analysis
- **Rich** — Beautiful terminal output with progress tracking
- **GCC (MSYS2)** — C compilation for test targets

---

<p align="center">
  <b>Built by Aaron Alva</b><br>
  <a href="https://bunny-sysd.github.io/portfolio/">Portfolio</a> · 
  <a href="https://github.com/Bunny-sysd">GitHub</a> · 
  <a href="https://tryhackme.com/p/354221973">TryHackMe</a>
</p>
