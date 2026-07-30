from datetime import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, func, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base

class Enrichment(Base):
    __tablename__ = "enrichments"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # virustotal, abuseipdb, etc.
    status: Mapped[str] = mapped_column(String(50), default="success") # success, cached, failed, skipped
    summary_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_response: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    ioc: Mapped["IOC"] = relationship(back_populates="enrichments")
