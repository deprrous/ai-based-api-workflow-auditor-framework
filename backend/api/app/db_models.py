from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanRunRecord(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    current_stage: Mapped[str] = mapped_column(String(64), nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flagged_paths: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk: Mapped[str] = mapped_column(String(32), nullable=False)
    workflow_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    workflow: Mapped[WorkflowGraphRecord | None] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        uselist=False,
    )
    events: Mapped[list[ScanEventRecord]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanEventRecord.id",
    )


class WorkflowGraphRecord(Base):
    __tablename__ = "workflow_graphs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=True, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    flagged_paths: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    nodes_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    edges_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[ScanRunRecord | None] = relationship(back_populates="workflow")


class ScanEventRecord(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    scan: Mapped[ScanRunRecord] = relationship(back_populates="events")
