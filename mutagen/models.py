
from pydantic import BaseModel


class FuzzPayload(BaseModel):
    args: list[str]
    input_data: str | None = ""
    vuln_type: str
    reason: str
    severity: str
    cwe: str | None = ""
    data_flow: list[str] | None = []
    confidence_score: int | None = 5
    mitigations_detected: list[str] | None = []

class FuzzPayloadList(BaseModel):
    payloads: list[FuzzPayload]

