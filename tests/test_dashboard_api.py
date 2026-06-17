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
        "exploit_code": "import sys"
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
    
    # CISO gets all scans
    headers_ciso = {"Authorization": f"Bearer {ciso_token}"}
    response = client.get("/api/scans", headers=headers_ciso)
    assert response.status_code == 200
    scans_ciso = response.json()
    assert len(scans_ciso) >= 1
    
    # Unauthorized request (no token)
    response = client.get("/api/scans")
    assert response.status_code == 401
