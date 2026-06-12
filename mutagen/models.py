from pydantic import BaseModel

class FuzzPayload(BaseModel):
    args: list[str]
    vuln_type: str
    reason: str
    severity: str
    cwe: str
