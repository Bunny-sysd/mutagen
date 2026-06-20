from pydantic import BaseModel
from typing import Optional

class FuzzPayload(BaseModel):
    args: list[str]
    input_data: Optional[str] = ""
    vuln_type: str
    reason: str
    severity: str
    cwe: Optional[str] = ""
    data_flow: Optional[list[str]] = []
    confidence_score: Optional[int] = 5
    mitigations_detected: Optional[list[str]] = []

class FuzzPayloadList(BaseModel):
    payloads: list[FuzzPayload]

