
from pydantic import BaseModel


class FuzzPayload(BaseModel):
    args: list[str]
    input_data: str | None = ""
    raw_bytes_hex: str | None = None
    vuln_type: str
    reason: str
    severity: str
    cwe: str | None = ""
    data_flow: list[str] | None = []
    confidence_score: int | None = 5
    mitigations_detected: list[str] | None = []

class FuzzPayloadList(BaseModel):
    payloads: list[FuzzPayload]


class FuzzSequence(BaseModel):
    sequence: list[str]
    vuln_type: str
    reason: str
    severity: str
    cwe: str | None = ""


class FuzzSequenceList(BaseModel):
    sequences: list[FuzzSequence]


class PayloadItem(BaseModel):
    args: list[str] = []
    input_data: str | None = ""
    raw_bytes_hex: str | None = None
    reason: str = ""


class PayloadList(BaseModel):
    payloads: list[PayloadItem]



