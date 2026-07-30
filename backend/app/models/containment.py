from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, func, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List
from app.models.base import Base

class ContainmentAction(Base):
    __tablename__ = "containment_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)  # block_ip, isolate_host, ticket
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, approved, executing, executed, failed
    input_parameters: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    operator_email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Relationships
    case: Mapped["Case"] = relationship(back_populates="containment_actions")
    audit_logs: Mapped[List["AuditLog"]] = relationship(back_populates="containment_action")
