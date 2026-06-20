# Enterprise Scaling & Multi-Language Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform Mutagen from a localized CLI fuzzer into an enterprise-grade AppSec platform featuring a multi-user cloud dashboard, automated ticketing integrations, distributed GPU load-balancing, regulatory compliance mapping, and support for Java, Go, and C#.

**Architecture:** 
Introduce a distributed load-balancer for local Ollama swarms; a centralized FastAPI backend for report collection and JWT-based RBAC; a compliance mapping module matching CWEs to PCI-DSS/SOC2; webhook alerts for ticketing automation; and language-specific target parsers for multi-stack code audits.

**Tech Stack:** FastAPI, SQLite (or PostgreSQL), Pytest, Docker/Kubernetes, Pydantic, HSL/Vanilla CSS.

---

### Task 1: Regulatory Compliance Mapping (CWE to PCI-DSS & SOC2)

**Files:**
- Create: `mutagen/compliance.py`
- Modify: `mutagen/reporter.py`
- Test: `tests/test_compliance.py`

**Step 1: Write the failing test**
Create `tests/test_compliance.py` to check that the mapping database correctly associates CWE-120 and CWE-134 with PCI-DSS Requirements and SOC2 Security Criteria:
```python
from mutagen.compliance import map_cwe_to_compliance

def test_cwe_compliance_mapping():
    mapping = map_cwe_to_compliance("CWE-120")
    assert "PCI-DSS" in mapping
    assert "SOC2" in mapping
    assert "Requirement 6" in mapping["PCI-DSS"]
```

**Step 2: Run test to verify it fails**
Run: `.venv\Scripts\pytest tests/test_compliance.py`
Expected: FAIL with `ModuleNotFoundError` or `ImportError`.

**Step 3: Write minimal implementation**
Create `mutagen/compliance.py`:
```python
COMPLIANCE_MAP = {
    "CWE-120": {
        "PCI-DSS": "Requirement 6.2.4 (Buffer overflow prevention)",
        "SOC2": "CC7.1, CC7.2 (Vulnerability management & mitigation)"
    },
    "CWE-134": {
        "PCI-DSS": "Requirement 6.2.4 (Format string vulnerability prevention)",
        "SOC2": "CC7.1 (Input validation controls)"
    },
    "CWE-843": {
        "PCI-DSS": "Requirement 6.2.4 (Type confusion & memory safety controls)",
        "SOC2": "CC7.1, CC7.2 (Secure system design)"
    }
}

def map_cwe_to_compliance(cwe_id: str) -> dict:
    cwe_clean = cwe_id.upper().strip()
    return COMPLIANCE_MAP.get(cwe_clean, {
        "PCI-DSS": "Requirement 6.2.4 (General secure application development)",
        "SOC2": "CC7.1 (System boundaries validation)"
    })
```

**Step 4: Run test to verify it passes**
Run: `.venv\Scripts\pytest tests/test_compliance.py`
Expected: PASS

**Step 5: Commit**
```bash
git add mutagen/compliance.py tests/test_compliance.py
git commit -m "feat: add compliance framework mapping database"
```

---

### Task 2: Automated Webhook Notifications

**Files:**
- Modify: `mutagen/cli.py`
- Modify: `mutagen/reporter.py`
- Test: `tests/test_webhooks.py`

**Step 1: Write the failing test**
Create `tests/test_webhooks.py` to assert that Mutagen correctly fires a POST request to a configured webhook URL:
```python
import pytest
from unittest.mock import patch
from mutagen.reporter import save_crash_report

@patch("requests.post")
def test_webhook_alert_firing(mock_post):
    save_crash_report([], "test_webhook", 1, webhook_url="http://example.com/webhook")
    assert mock_post.called
```

**Step 2: Run test to verify it fails**
Run: `.venv\Scripts\pytest tests/test_webhooks.py`
Expected: FAIL due to missing `webhook_url` argument support.

**Step 3: Write minimal implementation**
Modify `mutagen/reporter.py` parameter lists and logic to accept `webhook_url: str = ""` and trigger a non-blocking webhook POST event containing JSON payload reports if specified.

**Step 4: Run test to verify it passes**
Run: `.venv\Scripts\pytest tests/test_webhooks.py`
Expected: PASS

**Step 5: Commit**
```bash
git add mutagen/reporter.py tests/test_webhooks.py
git commit -m "feat: implement automated webhook alerts for ticket routing"
```

---

### Task 3: Distributed Load-Balancer for Local AI Swarms

**Files:**
- Create: `mutagen/swarm_balancer.py`
- Modify: `mutagen/engines/ollama.py`
- Test: `tests/test_swarm_balancer.py`

**Step 1: Write the failing test**
Create `tests/test_swarm_balancer.py` to assert the swarm balancer distributes API requests in a round-robin fashion over multiple target URLs:
```python
from mutagen.swarm_balancer import SwarmBalancer

def test_round_robin_routing():
    balancer = SwarmBalancer(["http://10.0.0.1:11434", "http://10.0.0.2:11434"])
    assert balancer.get_next_node() == "http://10.0.0.1:11434"
    assert balancer.get_next_node() == "http://10.0.0.2:11434"
```

**Step 2: Run test to verify it fails**
Run: `.venv\Scripts\pytest tests/test_swarm_balancer.py`
Expected: FAIL with `ModuleNotFoundError`.

**Step 3: Write minimal implementation**
Create `mutagen/swarm_balancer.py` with thread-safe queue round-robin scheduling and update `OllamaEngine` in `mutagen/engines/ollama.py` to route queries using the balancer if multiple comma-separated URLs are provided in the configuration.

**Step 4: Run test to verify it passes**
Run: `.venv\Scripts\pytest tests/test_swarm_balancer.py`
Expected: PASS

**Step 5: Commit**
```bash
git add mutagen/swarm_balancer.py mutagen/engines/ollama.py tests/test_swarm_balancer.py
git commit -m "feat: implement distributed load balancer for local AI swarms"
```

---

### Task 4: Multi-Language Target Audits (Java, Go, C# Support)

**Files:**
- Modify: `mutagen/cli.py`
- Modify: `mutagen/compiler.py`
- Test: `tests/test_multilang.py`

**Step 1: Write the failing test**
Create `tests/test_multilang.py` to check that `.java`, `.go`, and `.cs` targets are accepted and correctly routed to compile checks:
```python
from mutagen.cli import is_supported_language

def test_language_support():
    assert is_supported_language(".go") is True
    assert is_supported_language(".java") is True
    assert is_supported_language(".cs") is True
```

**Step 2: Run test to verify it fails**
Run: `.venv\Scripts\pytest tests/test_multilang.py`
Expected: FAIL with `NameError` or `ImportError`.

**Step 3: Write minimal implementation**
Modify `mutagen/cli.py` and `mutagen/compiler.py` to detect Java, Go, and C# files, adding mock/shell command wrapper routing for `go build`, `javac`, and `dotnet build` respectively.

**Step 4: Run test to verify it passes**
Run: `.venv\Scripts\pytest tests/test_multilang.py`
Expected: PASS

**Step 5: Commit**
```bash
git add mutagen/cli.py mutagen/compiler.py tests/test_multilang.py
git commit -m "feat: add multi-language support extensions"
```

---

### Task 5: Cloud Dashboard & RBAC Server

**Files:**
- Create: `mutagen/dashboard/server.py`
- Create: `mutagen/dashboard/auth.py`
- Test: `tests/test_dashboard_api.py`

**Step 1: Write the failing test**
Create `tests/test_dashboard_api.py` to check endpoint routing, RBAC tokens validation, and user role separation (Developer vs Admin vs CISO):
```python
from mutagen.dashboard.auth import generate_jwt, verify_role

def test_role_verification():
    token = generate_jwt(username="alice", role="developer")
    assert verify_role(token, allowed=["developer", "ciso"]) is True
    assert verify_role(token, allowed=["ciso"]) is False
```

**Step 2: Run test to verify it fails**
Run: `.venv\Scripts\pytest tests/test_dashboard_api.py`
Expected: FAIL with `ModuleNotFoundError`.

**Step 3: Write minimal implementation**
Create a lightweight API server in `mutagen/dashboard/server.py` and authorization mechanisms in `mutagen/dashboard/auth.py` validating roles for multi-tenant scan reporting access.

**Step 4: Run test to verify it passes**
Run: `.venv\Scripts\pytest tests/test_dashboard_api.py`
Expected: PASS

**Step 5: Commit**
```bash
git add mutagen/dashboard/ tests/test_dashboard_api.py
git commit -m "feat: implement centralized dashboard API and RBAC"
```
