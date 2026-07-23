from typing import Any

from pydantic import BaseModel, Field


class VulnerabilityDetail(BaseModel):
    vuln_type: str
    cwe: str
    severity: str
    line_number: int
    code_snippet: str
    metadata: dict[str, Any] = Field(default_factory=dict)

class CrashPayload(BaseModel):
    args: list[str]
    input_data: str
    exit_code: int | None = None
    crash_type: str | None = None
    stdout: str | None = None
    stderr: str | None = None

class ProgramContext(BaseModel):
    target_path: str
    language: str
    os_platform: str
    source_code: str
    ast_tree_json: str | None = None
    vulnerabilities: list[VulnerabilityDetail] = Field(default_factory=list)
    active_payloads: list[CrashPayload] = Field(default_factory=list)
    proposed_patches: dict[str, str] = Field(default_factory=dict)  # patch_id -> source
    verification_status: str = "UNVERIFIED"  # UNVERIFIED, VERIFIED_SECURE, REGRESSION_FAILED
    delivery_mode: str = "args"
    notepad: list[str] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)
