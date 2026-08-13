from typing import Any

from pydantic import BaseModel, Field, field_validator


class VulnerabilityDetail(BaseModel):
    vuln_type: str
    cwe: str
    severity: str
    line_number: int
    code_snippet: str
    verification_status: str = "UNCONFIRMED_RISK"  # "VERIFIED_SAFE" | "LIKELY_FALSE_POSITIVE" | "UNGROUNDED_FINDING" | "UNCONFIRMED_RISK" | "VERIFIED_RISK"
    verification_annotation: str = ""
    confidence: str = "HIGH"                       # "HIGH" | "MEDIUM" | "LOW"
    is_false_positive_risk: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_any(cls, obj: Any) -> "VulnerabilityDetail":
        """
        Universal factory method that coerces dicts, StaticFinding dataclasses, Pydantic objects,
        or raw strings into a strictly validated VulnerabilityDetail canonical model.
        Fails loudly with TypeError if obj cannot be converted.
        """
        if isinstance(obj, VulnerabilityDetail):
            return obj
        if isinstance(obj, dict):
            meta = dict(obj.get("metadata", {}))
            if "reason" not in meta and "reason" in obj:
                meta["reason"] = str(obj.get("reason", ""))
            
            v_stat = obj.get("verification_status", meta.get("verification_status", "UNCONFIRMED_RISK"))
            v_annot = obj.get("verification_annotation", meta.get("verification_annotation", ""))
            v_conf = obj.get("confidence", meta.get("confidence", "HIGH"))
            v_fp = obj.get("is_false_positive_risk", meta.get("is_false_positive_risk", False))
            
            meta["verification_status"] = v_stat
            meta["verification_annotation"] = v_annot
            meta["confidence"] = v_conf
            meta["is_false_positive_risk"] = v_fp

            return cls(
                vuln_type=str(obj.get("vuln_type", "Memory Corruption")),
                cwe=str(obj.get("cwe", "CWE-120")),
                severity=str(obj.get("severity", "critical")),
                line_number=int(obj.get("line_number", obj.get("line", 1))),
                code_snippet=str(obj.get("code_snippet", obj.get("context_snippet", obj.get("snippet", "")))),
                verification_status=str(v_stat),
                verification_annotation=str(v_annot),
                confidence=str(v_conf),
                is_false_positive_risk=bool(v_fp),
                metadata=meta
            )
        if hasattr(obj, "call_name") or hasattr(obj, "cwe"):
            # StaticFinding dataclass or similar AST object
            call_name = str(getattr(obj, "call_name", getattr(obj, "name", "unknown")))
            cwe = str(getattr(obj, "cwe", "CWE-120"))
            severity = str(getattr(obj, "severity", "medium"))
            line_num = int(getattr(obj, "line", getattr(obj, "line_number", 1)))
            snippet = str(getattr(obj, "context_snippet", getattr(obj, "code_snippet", getattr(obj, "snippet", ""))))
            pattern_type = str(getattr(obj, "pattern_type", "Potential Danger"))
            vuln_type = f"Static Finding ({call_name})" if call_name != "unknown" else f"Static Finding ({pattern_type})"

            return cls(
                vuln_type=vuln_type,
                cwe=cwe,
                severity=severity,
                line_number=line_num,
                code_snippet=snippet,
                metadata={"reason": f"Dangerous call '{call_name}' identified by static analyzer"}
            )
        if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
            return cls.from_any(obj.dict())

        raise TypeError(
            f"[StateBoundaryError] Cannot convert object of type '{type(obj).__name__}' to VulnerabilityDetail. "
            f"Expected dict, StaticFinding, or VulnerabilityDetail. Received: {obj!r}"
        )


class CrashPayload(BaseModel):
    args: list[str] = Field(default_factory=list)
    input_data: str = ""
    raw_bytes_hex: str | None = None
    reason: str | None = None
    exit_code: int | None = None
    crash_type: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    container_id: str | None = None
    container_image: str | None = None
    container_image_digest: str | None = None

    @classmethod
    def from_any(cls, obj: Any) -> "CrashPayload":
        """
        Universal factory method that coerces dicts, strings, bytes, or payload objects
        into a strictly validated CrashPayload canonical model.
        Fails loudly with TypeError if obj cannot be converted.
        """
        if isinstance(obj, CrashPayload):
            return obj
        if isinstance(obj, dict):
            raw_args = obj.get("args", [])
            args_list = [str(a) for a in raw_args] if isinstance(raw_args, list) else [str(raw_args)]
            return cls(
                args=args_list,
                input_data=str(obj.get("input_data", "")),
                raw_bytes_hex=obj.get("raw_bytes_hex"),
                reason=obj.get("reason"),
                exit_code=obj.get("exit_code"),
                crash_type=obj.get("crash_type"),
                stdout=obj.get("stdout"),
                stderr=obj.get("stderr"),
                container_id=obj.get("container_id"),
                container_image=obj.get("container_image"),
                container_image_digest=obj.get("container_image_digest")
            )
        if isinstance(obj, str):
            return cls(args=[obj], input_data=obj, reason="Raw string payload")
        if isinstance(obj, bytes):
            return cls(args=[], input_data="", raw_bytes_hex=obj.hex(), reason="Raw bytes payload")
        if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
            return cls.from_any(obj.dict())

        raise TypeError(
            f"[StateBoundaryError] Cannot convert object of type '{type(obj).__name__}' to CrashPayload. "
            f"Expected dict, str, bytes, or CrashPayload. Received: {obj!r}"
        )

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


class PatchProposal(BaseModel):
    patch_id: str = "primary_patch"
    patched_code: str
    revision: int = 1
    verification_status: str = "UNVERIFIED"
    error_message: str | None = None


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
    skip_flagged_findings: bool = False

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def validate_vulnerabilities(cls, v: Any) -> list[VulnerabilityDetail]:
        if not isinstance(v, list):
            raise TypeError(f"[StateBoundaryError] vulnerabilities must be a list, got {type(v).__name__}")
        return [VulnerabilityDetail.from_any(item) for item in v]

    @field_validator("active_payloads", mode="before")
    @classmethod
    def validate_active_payloads(cls, v: Any) -> list[CrashPayload]:
        if not isinstance(v, list):
            raise TypeError(f"[StateBoundaryError] active_payloads must be a list, got {type(v).__name__}")
        return [CrashPayload.from_any(item) for item in v]

    def add_vulnerability(self, item: Any) -> VulnerabilityDetail:
        """Helper to append and validate a vulnerability detail object to context."""
        detail = VulnerabilityDetail.from_any(item)
        self.vulnerabilities.append(detail)
        return detail

    def add_payload(self, item: Any) -> CrashPayload:
        """Helper to append and validate a crash payload object to context."""
        payload = CrashPayload.from_any(item)
        self.active_payloads.append(payload)
        return payload

    def get_primary_patch(self) -> str | None:
        """Returns primary patch code string if available."""
        return self.proposed_patches.get("primary_patch")

    def set_primary_patch(self, code: str) -> None:
        """Sets primary patch code string."""
        self.proposed_patches["primary_patch"] = code
