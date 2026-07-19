from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, UniqueConstraint, Table, Column, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List
from app.models.base import Base

# Association Table for Many-to-Many relationship between Alert and IOC
alert_iocs = Table(
    "alert_iocs",
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)

class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ip, domain, hash_md5, hash_sha1, hash_sha256, url
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Constraints
    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
    )

    # Relationships
    alerts: Mapped[List["Alert"]] = relationship(
        secondary=alert_iocs,
        back_populates="iocs"
    )
    enrichments: Mapped[List["Enrichment"]] = relationship(
        back_populates="ioc",
        cascade="all, delete-orphan"
    )
