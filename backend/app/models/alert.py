from datetime import datetime
from sqlalchemy import String, Text, DateTime, ForeignKey, func, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List
from app.models.base import Base

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    alert_id: Mapped[str] = mapped_column(String(100), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    case: Mapped["Case"] = relationship(back_populates="alerts")
    iocs: Mapped[List["IOC"]] = relationship(
        secondary="alert_iocs",
        back_populates="alerts"
    )
    mitre_techniques: Mapped[List["MITRETechnique"]] = relationship(
        secondary="alert_mitre_techniques",
        back_populates="alerts"
    )
