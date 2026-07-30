import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, ForeignKey, JSON, Uuid, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(UUID(as_uuid=True), "postgresql"),
        primary_key=True,
        default=uuid.uuid4
    )
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True)
    action_id: Mapped[int | None] = mapped_column(ForeignKey("containment_actions.id", ondelete="CASCADE"), nullable=True)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)  # user ID/email or system component
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # Case_Approval, Case_Denial, Action_Executed, etc.
    before_state: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    after_state: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    containment_action: Mapped["ContainmentAction"] = relationship(back_populates="audit_logs")
