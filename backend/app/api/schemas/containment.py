from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from typing import Any, Optional

class ActionDenyRequest(BaseModel):
    denial_reason: str = Field(..., min_length=3, description="Reason for denying containment action recommendation")

class ContainmentActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    action_type: str
    target: Optional[str] = None
    status: str
    input_parameters: Optional[dict[str, Any]] = None
    mock_result: Optional[dict[str, Any]] = None
    requested_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    denied_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    operator_id: Optional[str] = None
    operator_email: Optional[str] = None
    denial_reason: Optional[str] = None

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: Optional[int] = None
    action_id: Optional[int] = None
    actor: str
    action: str
    before_state: Optional[dict[str, Any]] = None
    after_state: Optional[dict[str, Any]] = None
    created_at: datetime
