# Mutagen Developer & Agent Handbook (AGENT.md)

Welcome! This handbook is designed to help AI coding agents and human developers quickly orient themselves in the Mutagen repository. 

> [!NOTE]
> AI agents should also refer to [agent.md](file:///c:/mutagen/agent.md) for a curated map of developer skills, tools, and test workflows.

---

## Active Skills for Mutagen Development

When planning updates or debugging errors, cross-reference these core skills:

### 1. Systematic Debugging & Testing
- **Skill Reference**: [systematic-debugging](file:///C:/Users/admin/.gemini/config/skills/systematic-debugging/SKILL.md) / [test-driven-development](file:///C:/Users/admin/.gemini/config/skills/test-driven-development/SKILL.md)
- **Application**: Always write a unit test covering edge-case inputs (e.g. payload length boundary checking, parser edge cases) before implementing code fixes. Run:
  ```powershell
  python -m pytest tests/ -v
  ```
  Ensure all 143 unit tests pass.

### 2. CI/CD Pipeline Safety Boundaries
- **Skill Reference**: [github-actions-templates](file:///C:/Users/admin/.gemini/config/skills/github-actions-templates/SKILL.md) / [red-team-tactics](file:///C:/Users/admin/.gemini/config/skills/red-team-tactics/SKILL.md)
- **Application**: Maintain the security gate configured in [ci_helper.py](file:///c:/mutagen/mutagen/ci_helper.py). Pre-compiled binaries submitted in pull requests must **never** be executed to prevent malicious takeover of runners.

### 3. Containerized Sandboxing (Docker Fuzzing)
- **Skill Reference**: [security-auditor](file:///C:/Users/admin/.gemini/config/skills/security-auditor/SKILL.md)
- **Application**: When debugging `--sandbox docker` flags in [executor.py](file:///c:/mutagen/mutagen/executor.py), guarantee that memory constraints (`--memory=512m`) and disabled networking (`--network=none`) are enforced strictly. Standardize sandbox interaction to only use stdout logs for basic block coverage tracing rather than local container filesystems.

### 4. Code Refactoring & API Integration
- **Skill Reference**: [api-patterns](file:///C:/Users/admin/.gemini/config/skills/api-patterns/SKILL.md) / [simplify-code](file:///C:/Users/admin/.gemini/config/skills/simplify-code/SKILL.md)
- **Application**: When updating webhook dispatchers in [reporter.py](file:///c:/mutagen/mutagen/reporter.py), enforce authentication validation headers (`--webhook-header`) and SHA-256 HMAC payload signatures.

---

## Key Architecture Map
- **CLI Routing**: [cli.py](file:///c:/mutagen/mutagen/cli.py)
- **Core Fuzzer Loop**: [core.py](file:///c:/mutagen/mutagen/core.py)
- **Instrumentation & Coverage Engine**: [instrumenter.py](file:///c:/mutagen/mutagen/instrumenter.py) & [executor.py](file:///c:/mutagen/mutagen/executor.py)
- **Decompilation Pipeline**: [decompiler.py](file:///c:/mutagen/mutagen/decompiler.py)
