from sqlalchemy import String, ForeignKey, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List
from app.models.base import Base

# Association Table for Many-to-Many relationship between Alert and MITRETechnique
alert_mitre_techniques = Table(
    "alert_mitre_techniques",
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("mitre_technique_id", ForeignKey("mitre_techniques.id", ondelete="CASCADE"), primary_key=True),
)

class MITRETechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[int] = mapped_column(primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False) # e.g. T1110
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(255), nullable=False) # e.g. Credential Access

    # Relationships
    alerts: Mapped[List["Alert"]] = relationship(
        secondary=alert_mitre_techniques,
        back_populates="mitre_techniques"
    )
