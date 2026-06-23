# Mutagen Command Line Interface (CLI) Usage Guide

This document lists all available command-line arguments, options, and environmental configuration settings for running the Mutagen AI fuzzer.

---

## Basic Command Format

```bash
python mutagen.py -t <target_file> [options]
```

Or run all default targets:
```bash
python run_all.py
```

---

## Command Line Options Reference

| Argument | Shorthand | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--target` | `-t` | String | `None` | Path to the target source file (e.g., `targets/01_buffer_overflow.c`) or compiled binary. |
| `--ci` | | Flag | `False` | CI/CD mode: scans and fuzzes modified files detected via git diff since `origin/master`. |
| `--api-key` | `-k` | String | `None` | API Key for the LLM provider. Falls back to environment variables if not passed. |
| `--max-payloads` | | Integer | `5` | Maximum number of payloads the AI should generate per iteration. |
| `--timeout` | | Integer | `5` | Execution timeout in seconds for running the compiled binary. |
| `--debug` | | Flag | `False` | Enable verbose debugging. Logs are written to `mutagen_debug.log`. |
| `--provider` | | Choice | `gemini` | LLM provider to use. Choices: `gemini`, `openai`, `claude`, `ollama`. |
| `--model` | | String | `""` | Specific model string (e.g., `gpt-4o`, `claude-3-5-sonnet-latest`, `gemini-2.5-flash`). |
| `--delivery` | | String | `args` | Input delivery method for the binary. Choices: `args`, `stdin`, `tcp:<port>`. |
| `--max-patch-retries`| | Integer | `3` | Maximum self-healing loop retries for fixing failing patches. |
| `--decompile-all` | | Flag | `False` | Decompile all binary functions when auditing compiled files (slower but thorough). |
| `--ghidra-path` | | String | `""` | Custom path to local Ghidra install folder (overrides auto-detection). |
| `--profile` | | Choice | `legacy-audit` | Auditing rule profile. Choices: `legacy-audit`, `supply-chain`, `malware-triage`. |
| `--static-only` | | Flag | `False` | Only perform AI static code analysis, skipping compiled binary execution. |
| `--webhook-url` | | String | `""` | Webhook URL to dispatch JSON-formatted scan results to (e.g., Slack, n8n, Jira). |
| `--sandbox` | | Choice | `none` | Isolation sandbox engine for executing binaries. Choices: `none`, `docker`. |
| `--coverage` | | Flag | `False` | Enable coverage-guided hybrid mutation loop tracking. |

---

## Practical Examples

### 1. Fuzz a C target with coverage-guided feedback and Gemini
```bash
python mutagen.py -t targets/16_cve_2026_6691_mongoc_sasl.c --coverage --max-payloads 3
```

### 2. Isolate target execution in a secure Docker sandbox
```bash
python mutagen.py -t targets/04_use_after_free.c --sandbox docker --delivery stdin
```

### 3. Fuzz a TCP Server using local Ollama model Swarms
```bash
python mutagen.py -t targets/09_network_server.c --provider ollama --model qwen2.5-coder:7b --delivery tcp:8080
```

### 4. Run static-only supply chain audit on a repository
```bash
python mutagen.py -t targets/11_complex_auth.c --static-only --profile supply-chain
```
