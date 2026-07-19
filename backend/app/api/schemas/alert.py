from pydantic import BaseModel, Field
from typing import List, Dict, Any

class IOCIn(BaseModel):
    ioc_type: str = Field(..., description="Type of indicator, e.g. ip, domain, hash_sha256")
    value: str = Field(..., description="The raw indicator value")

class AlertCreate(BaseModel):
    alert_id: str = Field(..., description="External alert identifier")
    source: str = Field(..., description="The source tool generating the alert")
    severity: str = Field(..., description="Severity of the alert")
    title: str = Field(..., description="Title of the alert")
    description: str | None = Field(None, description="Optional description of the alert")
    iocs: List[IOCIn] = Field(default=[], description="List of indicators associated with the alert")
    raw_payload: Dict[str, Any] = Field(default={}, description="Raw threat event payload")
