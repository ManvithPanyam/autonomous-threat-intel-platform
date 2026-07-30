from datetime import datetime
from sqlalchemy import String, Text, Integer, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List
from app.models.base import Base

class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open")  # open, under_investigation, resolved
    severity: Mapped[str] = mapped_column(String(50), default="low")   # low, medium, high, critical
    severity_score: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    severity_tier: Mapped[str | None] = mapped_column(String(50), nullable=True, default="Low")
    severity_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    technique_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    technique_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    analyst_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(), 
        onupdate=func.now()
    )

    @property
    def score(self):
        return self.severity_score

    @score.setter
    def score(self, value):
        self.severity_score = value

    # Relationships
    alerts: Mapped[List["Alert"]] = relationship(back_populates="case")
    containment_actions: Mapped[List["ContainmentAction"]] = relationship(back_populates="case")
    prompt_logs: Mapped[List["LLMPromptLog"]] = relationship(back_populates="case")
