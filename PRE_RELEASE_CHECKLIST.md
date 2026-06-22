# Mutagen Pre-Release & Safety Checklist (PRE_RELEASE_CHECKLIST.md)

Before taking Mutagen public—whether you are pushing it to an open-source GitHub repository, publishing it for community feedback, or preparing a showcase for a portfolio—there are a few critical elements you should double-check.

Since Mutagen is both an AI agentic framework and a security tool, you need to ensure it is secure, reproducible, and legally protected.

---

## 🔒 1. Secrets & API Key Scrubbing (Highest Priority)
Before making a repository public, you must ensure no private credentials are baked into your codebase. GitHub gets crawled by automated bots seconds after a repo goes public, looking for leaked API keys.

* [x] **Check your `.gitignore`**: Ensure your `.env` file (or wherever you store your Gemini, OpenAI, and Anthropic keys) is explicitly listed so it never gets pushed to GitHub.
* [x] **Provide an `.env.example`**: Create a template file showing future users exactly what variables they need to configure without revealing your actual values (Done: [.env.example](file:///c:/mutagen/.env.example)):
  ```bash
  GEMINI_API_KEY=your_key_here
  OPENAI_API_KEY=your_key_here
  CLAUDE_API_KEY=your_key_here
  ```

---

## 📝 2. A Solid README.md (The Project's Face)
A polished README explains what your project does, how it works, and why people should care. For a highly technical tool like Mutagen, your README should include:

* [ ] **The Architecture Diagram**: Briefly map out the 5-phase agentic loop you built (Discovery, Payload Generation, Local Execution/Fuzzing, Patch Generation, and Verification).
* [ ] **Quick Start Guide**: Clear instructions on how to install dependencies and run a test target (e.g., `pip install -r requirements.txt` followed by the CLI command `python run_all.py`).
* [ ] **The Dashboard**: Mention the FastAPI dashboard and RBAC controls to highlight that this isn't just a basic script, but an entire enterprise framework.

---

## ⚖️ 3. Responsible Use & Security Disclaimer
Because Mutagen synthesizes functional security payloads to verify memory crashes and logic flaws, it crosses into dual-use security territory. It is highly recommended to add a clear disclaimer at the bottom of your README to protect yourself legally:

> ### ⚠️ Security Disclaimer
> This project is created strictly for defensive security research, automated patch verification, and educational engineering. It is designed to assist developers in identifying and fixing software vulnerabilities automatically. The authors are not responsible for any misuse or damage caused by this software.

---

## 📄 4. Open-Source Licensing
If you don't add a license file (`LICENSE`), your code is technically under exclusive copyright, meaning others cannot legally modify or contribute to it.

* [x] **MIT License**: (Already configured: [LICENSE](file:///c:/mutagen/LICENSE)). Excellent if you want maximum adoption. Anyone can use, modify, and distribute your code for any purpose, completely hands-off.
* [ ] **Apache 2.0 License**: Great for AI and security projects because it includes an explicit grant of patent rights from contributors and requires changes to be documented.

---

## 🛣️ 5. Absolute vs. Relative Paths
* [x] **Audit paths**: Review your code (especially configuration scripts or test execution lines) to ensure there are no hardcoded absolute file paths pointing to your local machine (e.g., `C:/Users/name/...` or `/home/ubuntu/projects/mutagen/targets/...`). Ensure all paths use relative lookups (`./targets/`) so the project runs out of the box on anyone else's machine. (Done: audited and replaced absolute Windows paths with relative lookups and dynamic user profile expansion in [cli.py](file:///c:/mutagen/mutagen/cli.py)).

---

Once those safety and operational checks are ticked off, your architecture is in a phenomenal state to be shown to the world.
