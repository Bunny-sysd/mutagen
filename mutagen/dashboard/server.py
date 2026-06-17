import uuid
import time
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from mutagen.dashboard.auth import get_token_payload

app = FastAPI(title="Mutagen Cloud Dashboard API")
security = HTTPBearer()

# Thread-safe in-memory database of scan reports
scans_db = []

class CrashPayload(BaseModel):
    args: List[str]
    vuln_type: str
    input_data: Optional[str] = ""

class ScanReportPayload(BaseModel):
    target: str
    crashes: List[CrashPayload]
    total_tested: int
    patch_code: Optional[str] = ""
    exploit_code: Optional[str] = ""

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
