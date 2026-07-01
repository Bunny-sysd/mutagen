from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class VulnerabilityDetail(BaseModel):
    vuln_type: str
    cwe: str
    severity: str
    line_number: int
    code_snippet: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class CrashPayload(BaseModel):
    args: List[str]
    input_data: str
    exit_code: Optional[int] = None
    crash_type: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

class ProgramContext(BaseModel):
    target_path: str
    language: str
    os_platform: str
    source_code: str
    ast_tree_json: Optional[str] = None
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)
    active_payloads: List[CrashPayload] = Field(default_factory=list)
    proposed_patches: Dict[str, str] = Field(default_factory=dict)  # patch_id -> source
    verification_status: str = "UNVERIFIED"  # UNVERIFIED, VERIFIED_SECURE, REGRESSION_FAILED
    delivery_mode: str = "args"
    logs: List[str] = Field(default_factory=list)
