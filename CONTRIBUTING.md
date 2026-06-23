# Contributing to Mutagen

Thank you for your interest in contributing to Mutagen! Contributions from the security and developer communities are what make tools like this robust and effective.

Please take a moment to review this guide before submitting issues, feature requests, or Pull Requests (PRs).

---

## 🛠 Setting Up Your Development Environment

Mutagen is built with Python 3 and integrates with local compilers and sandboxes.

1. **Fork and Clone the Repository**:
   ```bash
   git clone https://github.com/Bunny-sysd/mutagen.git
   cd mutagen
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv .venv
   # Activate on Windows:
   .venv\Scripts\activate
   # Activate on macOS/Linux:
   source .venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up Your Environment Configuration**:
   Copy `.env.example` to `.env` and configure your API keys:
   ```bash
   cp .env.example .env
   ```

---

## Testing Your Changes

Before submitting any Pull Request, ensure the entire test suite passes:

```bash
python -m pytest tests/ -v
```

If you are adding new features (e.g., a new LLM provider, path handling, or sandbox option), please write corresponding unit tests under the `tests/` directory.

---

## Pull Request Guidelines

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/your-awesome-feature
   ```
2. **Commit with Clear Messages**:
   Follow semantic commit messages (e.g., `feat: add support for Ollama models`, `fix: handle connect timeout in Gemini engine`).
3. **Keep PRs Focused**: 
   Ensure your PR addresses a single problem or feature rather than packing unrelated modifications together.
4. **CI/CD Safety Rule**: 
   Any Pull Request that modifies compiled targets must pass the official GitHub Actions workflow. Note that pre-compiled binary targets submitted by external PRs are ignored/blocked during run-time for runner safety.

---

## Suggesting New Vulnerability Targets

If you'd like to add a new C/C++/Rust target binary or source file for the fuzzer to analyze:
1. Save the file under the `targets/` directory using standard numbering notation (e.g., `17_your_vuln_description.c`).
2. If possible, document the CVE or CWE mapping in the header comments.
3. Test your target using `python mutagen.py -t targets/17_your_vuln_description.c --max-payloads 3`.
