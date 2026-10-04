"""
SentinelAI Database Models

SQLAlchemy models for the SentinelAI SOC platform.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    JSON,
    ForeignKey,
)

from sqlalchemy.orm import Mapped, mapped_column

from database.session import Base


# ============================================================
# EVENTS
# ============================================================

class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    event_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
    )

    timestamp: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    protocol: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    attack_family: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    model_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    predicted_label: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    metadata_json: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


# ============================================================
# INCIDENTS
# ============================================================

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    incident_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="NEW",
    )

    severity: Mapped[str] = mapped_column(
        String(30),
        default="UNKNOWN",
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        default=0.0,
    )

    risk_score: Mapped[float] = mapped_column(
        Float,
        default=0.0,
    )

    attack_category: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    event_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    affected_users: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    affected_assets: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    source_ips: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    destination_ips: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    analyst_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# EVIDENCE
# ============================================================

class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"),
        index=True,
    )

    evidence_type: Mapped[str] = mapped_column(
        String(100),
    )

    description: Mapped[str] = mapped_column(
        Text,
    )

    source: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


# ============================================================
# INVESTIGATIONS
# ============================================================

class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"),
        index=True,
    )

    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    attack_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    analysis: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    investigation_plan: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    retrieved_sources: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    requires_human_review: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


# ============================================================
# RECOMMENDATIONS
# ============================================================

class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"),
        index=True,
    )

    recommendation: Mapped[str] = mapped_column(
        Text,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="AWAITING_APPROVAL",
    )

    analyst: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    analyst_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# ANALYST ACTIONS / AUDIT LOG
# ============================================================

class AnalystAction(Base):
    __tablename__ = "analyst_actions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"),
        index=True,
    )

    analyst: Mapped[str] = mapped_column(
        String(100),
    )

    action: Mapped[str] = mapped_column(
        String(100),
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


# ============================================================
# KNOWLEDGE DOCUMENTS
# ============================================================

class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    document_name: Mapped[str] = mapped_column(
        String(255),
    )

    source: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    content: Mapped[str] = mapped_column(
        Text,
    )

    metadata_json: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )