import pytest
from mutagen.dashboard.auth import generate_jwt, verify_role

def test_role_verification():
    # Test valid/invalid token roles
    token = generate_jwt(username="alice", role="developer")
    assert verify_role(token, allowed=["developer", "ciso"]) is True
    assert verify_role(token, allowed=["ciso"]) is False

def test_dashboard_api_rbac():
    from fastapi.testclient import TestClient
    from mutagen.dashboard.server import app
    
    client = TestClient(app)
    
    # Generate token for developer and ciso
    dev_token = generate_jwt(username="dev_user", role="developer")
    ciso_token = generate_jwt(username="ciso_user", role="ciso")
    
    # 1. Test scan report submission (POST /api/scans)
    # Developer should be allowed to submit a scan report
    scan_payload = {
        "target": "vuln.c",
        "crashes": [{"args": ["test"], "vuln_type": "buffer_overflow"}],
        "total_tested": 10,
        "patch_code": "void secure() {}",
        "exploit_code": "import sys",
        "original_code": "void vuln() {}"
    }
    
    headers_dev = {"Authorization": f"Bearer {dev_token}"}
    response = client.post("/api/scans", json=scan_payload, headers=headers_dev)
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    
    # 2. Test scan report access (GET /api/scans)
    # Developer gets only their scans
    response = client.get("/api/scans", headers=headers_dev)
    assert response.status_code == 200
    scans = response.json()
    assert len(scans) >= 1
    assert all(s["username"] == "dev_user" for s in scans)
    assert scans[0]["original_code"] == "void vuln() {}"
    
    # CISO gets all scans
    headers_ciso = {"Authorization": f"Bearer {ciso_token}"}
    response = client.get("/api/scans", headers=headers_ciso)
    assert response.status_code == 200
    scans_ciso = response.json()
    assert len(scans_ciso) >= 1
    
    # Unauthorized request (no token)
    response = client.get("/api/scans")
    assert response.status_code == 401


def test_dashboard_checklist_rbac_and_flow():
    from fastapi.testclient import TestClient
    from mutagen.dashboard.server import app
    
    client = TestClient(app)
    
    dev_token = generate_jwt(username="dev_user", role="developer")
    ciso_token = generate_jwt(username="ciso_user", role="ciso")
    
    headers_dev = {"Authorization": f"Bearer {dev_token}"}
    headers_ciso = {"Authorization": f"Bearer {ciso_token}"}
    
    # 1. Test GET /api/checklist
    response = client.get("/api/checklist", headers=headers_dev)
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 7
    assert items[0]["id"] == "scope-def"
    
    response = client.get("/api/checklist", headers=headers_ciso)
    assert response.status_code == 200
    
    # 2. Test POST /api/checklist/{item_id}
    # Developer should NOT be allowed to update
    response = client.post("/api/checklist/env-prep", json={"completed": True}, headers=headers_dev)
    assert response.status_code == 403
    
    # CISO should be allowed to update
    response = client.post("/api/checklist/env-prep", json={"completed": True}, headers=headers_ciso)
    assert response.status_code == 200
    assert response.json()["item"]["completed"] is True

    # 3. Test non-existent item ID
    response = client.post("/api/checklist/non-existent", json={"completed": True}, headers=headers_ciso)
    assert response.status_code == 404


def test_production_token_endpoint_protection(monkeypatch):
    # Dynamically inject MUTAGEN_ENV environment variable
    monkeypatch.setenv("MUTAGEN_ENV", "production")
    
    # Also patch server module variables so it registers immediately
    import mutagen.dashboard.server
    monkeypatch.setattr(mutagen.dashboard.server, "MUTAGEN_ENV", "production")
    
    from fastapi.testclient import TestClient
    from mutagen.dashboard.server import app
    
    client = TestClient(app)
    response = client.get("/api/token?username=admin_user&role=admin")
    assert response.status_code == 403
    assert "disabled in production mode" in response.json()["detail"]
