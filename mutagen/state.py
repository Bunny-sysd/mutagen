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
    args: list[str] = Field(default_factory=list)
    input_data: str = ""
    raw_bytes_hex: str | None = None
    exit_code: int | None = None
    crash_type: str | None = None
    stdout: str | None = None
    stderr: str | None = None

    @property
    def payload_bytes(self) -> bytes:
        """Returns raw byte representation of payload for file/stdin buffer pipelines."""
        if self.raw_bytes_hex:
            try:
                return bytes.fromhex(self.raw_bytes_hex)
            except Exception:
                pass
        if isinstance(self.input_data, bytes):
            return self.input_data
        if isinstance(self.input_data, str) and self.input_data:
            try:
                return self.input_data.encode('utf-8').decode('unicode_escape').encode('latin-1')
            except Exception:
                return self.input_data.encode('utf-8')
        return b""

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
    is_binary: bool = False
    decompiler_used: str = ""
    architecture: str = ""
    notepad: list[str] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)
    docker_available: bool = False
    sandboxed: bool = False
    user_confirmed_unsandboxed: bool = False
    ci_mode: bool = False
