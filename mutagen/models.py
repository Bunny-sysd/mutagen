from pydantic import BaseModel
from typing import Optional

class FuzzPayload(BaseModel):
    args: list[str]
    input_data: Optional[str] = ""
    vuln_type: str
    reason: str
    severity: str
    cwe: str
