# Mutagen Developer & Agent Handbook (AGENT.md)

Welcome! This handbook is designed to help AI coding agents and human developers quickly orient themselves in the Mutagen repository. 

> [!NOTE]
> AI agents should also refer to [agent.md](file:///c:/mutagen/agent.md) for a curated map of developer skills, tools, and test workflows.

---

## Active Skills for Mutagen Development

When planning updates or debugging errors, cross-reference these core skills:

### 1. Systematic Debugging & Testing
- **Skill Reference**: `systematic-debugging` / `test-driven-development`
- **Application**: Always write a unit test covering edge-case inputs (e.g. payload length boundary checking, parser edge cases) before implementing code fixes. Run:
  ```powershell
  python -m pytest tests/ -v
  ```
  Ensure all unit tests pass.

### 2. CI/CD Pipeline Safety Boundaries
- **Skill Reference**: `github-actions-templates` / `red-team-tactics`
- **Application**: Maintain the security gate configured in [ci_helper.py](file:///c:/mutagen/mutagen/ci_helper.py). Pre-compiled binaries submitted in pull requests must **never** be executed to prevent malicious takeover of runners.

### 3. Containerized Sandboxing (Docker Fuzzing)
- **Skill Reference**: `security-auditor`
- **Application**: When debugging `--sandbox docker` flags in [executor.py](file:///c:/mutagen/mutagen/executor.py), guarantee that memory constraints (`--memory=512m`) and disabled networking (`--network=none`) are enforced strictly. Standardize sandbox interaction to only use stdout logs for basic block coverage tracing rather than local container filesystems.

### 4. Code Refactoring & API Integration
- **Skill Reference**: `api-patterns` / `simplify-code`
- **Application**: When updating webhook dispatchers in [reporter.py](file:///c:/mutagen/mutagen/reporter.py), enforce authentication validation headers (`--webhook-header`) and SHA-256 HMAC payload signatures.

### 5. Secure Path Boundary Check Policy
- **Skill Reference**: `security-auditor` / `api-security-best-practices`
- **Application**: When checking path containment (e.g. limiting files strictly inside a workspace or sandbox directory), **never** use insecure prefix-based comparisons like `startswith()`. Always use segment-aware logic via `os.path.commonpath`. On Windows, normalize path casing to ensure case-insensitivity:
  ```python
  import os
  abs_target = os.path.abspath(target_file)
  workspace = os.path.abspath(workspace_dir)
  try:
      common = os.path.commonpath([workspace, abs_target])
      if os.name == 'nt':
          is_inside = (common.lower() == workspace.lower())
      else:
          is_inside = (common == workspace)
  except ValueError:
      is_inside = False
  ```

---

## Key Architecture Map
- **CLI Routing**: [cli.py](file:///c:/mutagen/mutagen/cli.py)
- **Core Fuzzer Loop**: [core.py](file:///c:/mutagen/mutagen/core.py)
- **Instrumentation & Coverage Engine**: [instrumenter.py](file:///c:/mutagen/mutagen/instrumenter.py) & [executor.py](file:///c:/mutagen/mutagen/executor.py)
- **Decompilation Pipeline**: [decompiler.py](file:///c:/mutagen/mutagen/decompiler.py)
