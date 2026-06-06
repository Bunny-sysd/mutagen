# 🧬 Mutagen — AI-Powered Zero-Day Fuzzer

<p align="center">
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
pip install google-generativeai rich

# 4. Set your free Gemini API key
$env:GEMINI_API_KEY="your-key-here"  # PowerShell
# export GEMINI_API_KEY="your-key-here"  # Bash

# 5. Run it!
python mutagen.py vuln.c
```

---

## 🎯 How It Works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Read .c    │────▶│  AI Analysis │────▶│  Compile &   │────▶│  Crash       │
│  Source Code│     │  (Gemini API)│     │  Fuzz Target │     │  Report      │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                           │                     │
                    Generate targeted      Monitor for
                    crash payloads        segfaults &
                                        access violations
```

1. **Analyze**: Mutagen reads the target C source code.
2. **AI Brain**: Sends the code to Gemini AI, which identifies vulnerabilities (buffer overflows, format strings, etc.) and generates targeted payloads.
3. **Execute**: Compiles the target with protections disabled, then injects each payload.
4. **Monitor**: Watches for crashes (segfaults, access violations, timeouts).
5. **Report**: Saves all crash-causing payloads to a JSON report in `crashes/`.

---

## 🛡️ Included Test Targets

| File | Vulnerability | Difficulty |
|------|--------------|------------|
| `vuln.c` | Buffer overflow via `strcpy()` | Easy |

---

## 📂 Project Structure

```
mutagen/
├── mutagen.py      # Main fuzzer engine
├── vuln.c          # Vulnerable test target
├── crashes/        # Auto-generated crash reports
├── .gitignore
└── README.md
```

---

## ⚠️ Legal Disclaimer

This tool is built for **educational and authorized security testing only**. Only use Mutagen on code you own or have explicit permission to test. Unauthorized use of fuzzing tools against systems you don't own is illegal.

---

## 🧠 Built With

- **Python 3.10+** — Core fuzzer logic
- **Google Gemini API** — AI-powered vulnerability analysis
- **Rich** — Beautiful terminal output
- **GCC (MSYS2)** — C compilation for test targets

---

<p align="center">
  <b>Built by Aaron Alva</b><br>
  <a href="https://bunny-sysd.github.io/portfolio/">Portfolio</a> · 
  <a href="https://github.com/Bunny-sysd">GitHub</a> · 
  <a href="https://tryhackme.com/p/354221973">TryHackMe</a>
</p>
