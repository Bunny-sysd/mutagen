import os
import time
import uuid
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mutagen.dashboard.auth import get_token_payload, generate_jwt

app = FastAPI(title="Mutagen Cloud Dashboard API")
security = HTTPBearer()

MUTAGEN_ENV = os.environ.get("MUTAGEN_ENV", "development").lower()

# Thread-safe in-memory database of scan reports
scans_db = []

# In-memory database of pentest checklist tasks
checklist_db = [
    {"id": "scope-def", "category": "Scope", "task": "Clarify testing purpose and define success criteria", "completed": True},
    {"id": "scope-bound", "category": "Scope", "task": "Define in-scope systems and document exclusions", "completed": True},
    {"id": "env-prep", "category": "Environment", "task": "Verify backup integrity and recovery procedures", "completed": False},
    {"id": "env-limit", "category": "Environment", "task": "Establish testing windows and staging limit safeguards", "completed": False},
    {"id": "mon-audit", "category": "Monitoring", "task": "Enable comprehensive audit logging on all endpoints", "completed": True},
    {"id": "mon-alert", "category": "Monitoring", "task": "Configure real-time alerts for security exception logs", "completed": False},
    {"id": "cleanup-auth", "category": "Remediation", "task": "Remove test artifacts and disable testing credentials", "completed": False},
]

# Serve static dashboard frontend on root
@app.get("/", response_class=FileResponse)
def read_index():
    static_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    return FileResponse(static_file)

# Dynamic JWT simulation endpoint for local testing
@app.get("/api/token")
def get_simulated_token(username: str, role: str):
    if MUTAGEN_ENV == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Simulated token generation is disabled in production mode"
        )
    if role not in ("developer", "ciso", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role specified")
    token = generate_jwt(username, role)
    return {"token": token}

class ChecklistUpdatePayload(BaseModel):
    completed: bool


class CrashPayload(BaseModel):
    args: list[str]
    vuln_type: str
    input_data: str | None = ""

class ScanReportPayload(BaseModel):
    target: str
    crashes: list[CrashPayload]
    total_tested: int
    patch_code: str | None = ""
    exploit_code: str | None = ""
    original_code: str | None = ""

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    payload = get_token_payload(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

@app.post("/api/scans", status_code=status.HTTP_201_CREATED)
def submit_scan(report: ScanReportPayload, user: dict = Depends(get_current_user)):
    if user.get("role") not in ("developer", "ciso", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted for this role"
        )

    scan_id = str(uuid.uuid4())
    scan_record = {
        "scan_id": scan_id,
        "username": user["username"],
        "role": user["role"],
        "target": report.target,
        "crashes": [c.model_dump() for c in report.crashes],
        "total_tested": report.total_tested,
        "patch_code": report.patch_code,
        "exploit_code": report.exploit_code,
        "original_code": report.original_code,
        "created_at": time.time()
    }
    scans_db.append(scan_record)
    return {"status": "success", "scan_id": scan_id}

@app.get("/api/scans")
def list_scans(user: dict = Depends(get_current_user)):
    role = user.get("role")
    username = user.get("username")

    if role in ("ciso", "admin"):
        return scans_db
    elif role == "developer":
        return [s for s in scans_db if s["username"] == username]
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role not permitted to view scans"
        )

@app.get("/api/checklist")
def get_checklist(user: dict = Depends(get_current_user)):
    if user.get("role") not in ("developer", "ciso", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role not permitted to view checklist"
        )
    return checklist_db

@app.post("/api/checklist/{item_id}")
def update_checklist_item(item_id: str, payload: ChecklistUpdatePayload, user: dict = Depends(get_current_user)):
    if user.get("role") not in ("ciso", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role not permitted to update checklist items"
        )
    for item in checklist_db:
        if item["id"] == item_id:
            item["completed"] = payload.completed
            return {"status": "success", "item": item}
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Checklist item not found"
    )
