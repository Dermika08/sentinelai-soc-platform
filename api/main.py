"""
SentinelAI FastAPI Backend

Provides REST APIs for:

- Health check
- Events
- Incidents
- Investigations
- Recommendations
- Analyst approval/rejection
- Incident resolution
- Metrics

This API is decision-support only.
No offensive or autonomous response actions are executed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database.session import SessionLocal
from database.models import (
    Event,
    Incident,
    Investigation,
    Recommendation,
    Evidence,
    AnalystAction,
)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="SentinelAI SOC API",
    description=(
        "AI-assisted cybersecurity incident investigation "
        "and response decision-support API."
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HELPERS
# ============================================================

def incident_to_dict(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "incident_id": incident.incident_id,
        "title": incident.title,
        "status": incident.status,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "risk_score": incident.risk_score,
        "attack_category": incident.attack_category,
        "first_seen": (
            incident.first_seen.isoformat()
            if incident.first_seen
            else None
        ),
        "last_seen": (
            incident.last_seen.isoformat()
            if incident.last_seen
            else None
        ),
        "event_count": incident.event_count,
        "affected_users": incident.affected_users or [],
        "affected_assets": incident.affected_assets or [],
        "source_ips": incident.source_ips or [],
        "destination_ips": incident.destination_ips or [],
        "analyst_notes": incident.analyst_notes,
        "created_at": (
            incident.created_at.isoformat()
            if incident.created_at
            else None
        ),
        "updated_at": (
            incident.updated_at.isoformat()
            if incident.updated_at
            else None
        ),
    }


def event_to_dict(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "event_id": event.event_id,
        "timestamp": (
            event.timestamp.isoformat()
            if event.timestamp
            else None
        ),
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "attack_family": event.attack_family,
        "model_score": event.model_score,
        "predicted_label": event.predicted_label,
        "severity": event.severity,
        "metadata": event.metadata_json or {},
        "created_at": (
            event.created_at.isoformat()
            if event.created_at
            else None
        ),
    }


def investigation_to_dict(
    investigation: Investigation,
) -> dict[str, Any]:

    return {
        "id": investigation.id,
        "incident_id": investigation.incident_id,
        "summary": investigation.summary,
        "attack_type": investigation.attack_type,
        "severity": investigation.severity,
        "confidence": investigation.confidence,
        "analysis": investigation.analysis or [],
        "investigation_plan": (
            investigation.investigation_plan or []
        ),
        "retrieved_sources": (
            investigation.retrieved_sources or []
        ),
        "requires_human_review": (
            investigation.requires_human_review
        ),
        "created_at": (
            investigation.created_at.isoformat()
            if investigation.created_at
            else None
        ),
    }


def recommendation_to_dict(
    recommendation: Recommendation,
) -> dict[str, Any]:

    return {
        "id": recommendation.id,
        "incident_id": recommendation.incident_id,
        "recommendation": recommendation.recommendation,
        "status": recommendation.status,
        "analyst": recommendation.analyst,
        "analyst_notes": recommendation.analyst_notes,
        "created_at": (
            recommendation.created_at.isoformat()
            if recommendation.created_at
            else None
        ),
        "updated_at": (
            recommendation.updated_at.isoformat()
            if recommendation.updated_at
            else None
        ),
    }


# ============================================================
# REQUEST SCHEMAS
# ============================================================

class AnalystDecision(BaseModel):

    analyst: str = "SOC Analyst"

    notes: str = ""


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": "SentinelAI SOC API",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ============================================================
# EVENTS
# ============================================================

@app.get("/events")
def get_events(
    limit: int = 100,
):

    if limit < 1 or limit > 1000:

        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 1000",
        )

    db = SessionLocal()

    try:

        events = (
            db.query(Event)
            .order_by(Event.timestamp.desc())
            .limit(limit)
            .all()
        )

        return {
            "count": len(events),
            "events": [
                event_to_dict(event)
                for event in events
            ],
        }

    finally:

        db.close()


# ============================================================
# INCIDENTS
# ============================================================

@app.get("/incidents")
def get_incidents():

    db = SessionLocal()

    try:

        incidents = (
            db.query(Incident)
            .order_by(Incident.created_at.desc())
            .all()
        )

        return {
            "count": len(incidents),
            "incidents": [
                incident_to_dict(incident)
                for incident in incidents
            ],
        }

    finally:

        db.close()


# ============================================================
# SINGLE INCIDENT
# ============================================================

@app.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if not incident:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        investigations = (
            db.query(Investigation)
            .filter(
                Investigation.incident_id
                == incident.id
            )
            .order_by(
                Investigation.created_at.desc()
            )
            .all()
        )

        recommendations = (
            db.query(Recommendation)
            .filter(
                Recommendation.incident_id
                == incident.id
            )
            .order_by(
                Recommendation.created_at.desc()
            )
            .all()
        )

        evidence = (
            db.query(Evidence)
            .filter(
                Evidence.incident_id
                == incident.id
            )
            .order_by(
                Evidence.created_at.asc()
            )
            .all()
        )

        return {
            "incident": incident_to_dict(
                incident
            ),
            "investigations": [
                investigation_to_dict(x)
                for x in investigations
            ],
            "recommendations": [
                recommendation_to_dict(x)
                for x in recommendations
            ],
            "evidence": [
                {
                    "id": x.id,
                    "type": x.evidence_type,
                    "description": x.description,
                    "source": x.source,
                    "confidence": x.confidence,
                    "created_at": (
                        x.created_at.isoformat()
                        if x.created_at
                        else None
                    ),
                }
                for x in evidence
            ],
        }

    finally:

        db.close()


# ============================================================
# INVESTIGATIONS
# ============================================================

@app.get("/incidents/{incident_id}/investigation")
def get_investigation(
    incident_id: str,
):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if not incident:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        investigation = (
            db.query(Investigation)
            .filter(
                Investigation.incident_id
                == incident.id
            )
            .order_by(
                Investigation.created_at.desc()
            )
            .first()
        )

        if not investigation:

            raise HTTPException(
                status_code=404,
                detail="Investigation not found",
            )

        return investigation_to_dict(
            investigation
        )

    finally:

        db.close()


# ============================================================
# RECOMMENDATIONS
# ============================================================

@app.get("/incidents/{incident_id}/recommendations")
def get_recommendations(
    incident_id: str,
):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if not incident:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        recommendations = (
            db.query(Recommendation)
            .filter(
                Recommendation.incident_id
                == incident.id
            )
            .order_by(
                Recommendation.created_at.desc()
            )
            .all()
        )

        return {
            "count": len(recommendations),
            "recommendations": [
                recommendation_to_dict(x)
                for x in recommendations
            ],
        }

    finally:

        db.close()


# ============================================================
# APPROVE INCIDENT
# ============================================================

@app.post("/incidents/{incident_id}/approve")
def approve_incident(
    incident_id: str,
    decision: AnalystDecision,
):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if not incident:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        incident.status = "APPROVED"
        incident.analyst_notes = decision.notes

        recommendations = (
            db.query(Recommendation)
            .filter(
                Recommendation.incident_id
                == incident.id
            )
            .all()
        )

        for recommendation in recommendations:

            recommendation.status = "APPROVED"
            recommendation.analyst = decision.analyst
            recommendation.analyst_notes = decision.notes

        action = AnalystAction(
            incident_id=incident.id,
            analyst=decision.analyst,
            action="APPROVED",
            notes=decision.notes,
        )

        db.add(action)

        db.commit()

        return {
            "success": True,
            "incident_id": incident.incident_id,
            "status": incident.status,
            "message": (
                "Recommendation approved by human analyst."
            ),
        }

    finally:

        db.close()


# ============================================================
# REJECT INCIDENT
# ============================================================

@app.post("/incidents/{incident_id}/reject")
def reject_incident(
    incident_id: str,
    decision: AnalystDecision,
):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if not incident:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        incident.status = "REJECTED"
        incident.analyst_notes = decision.notes

        recommendations = (
            db.query(Recommendation)
            .filter(
                Recommendation.incident_id
                == incident.id
            )
            .all()
        )

        for recommendation in recommendations:

            recommendation.status = "REJECTED"
            recommendation.analyst = decision.analyst
            recommendation.analyst_notes = decision.notes

        action = AnalystAction(
            incident_id=incident.id,
            analyst=decision.analyst,
            action="REJECTED",
            notes=decision.notes,
        )

        db.add(action)

        db.commit()

        return {
            "success": True,
            "incident_id": incident.incident_id,
            "status": incident.status,
            "message": (
                "Recommendation rejected by human analyst."
            ),
        }

    finally:

        db.close()


# ============================================================
# FALSE POSITIVE
# ============================================================

@app.post("/incidents/{incident_id}/false-positive")
def mark_false_positive(
    incident_id: str,
    decision: AnalystDecision,
):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if not incident:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        incident.status = "FALSE_POSITIVE"
        incident.analyst_notes = decision.notes

        action = AnalystAction(
            incident_id=incident.id,
            analyst=decision.analyst,
            action="FALSE_POSITIVE",
            notes=decision.notes,
        )

        db.add(action)

        db.commit()

        return {
            "success": True,
            "incident_id": incident.incident_id,
            "status": incident.status,
            "message": "Incident marked as false positive.",
        }

    finally:

        db.close()


# ============================================================
# RESOLVE INCIDENT
# ============================================================

@app.post("/incidents/{incident_id}/resolve")
def resolve_incident(
    incident_id: str,
    decision: AnalystDecision,
):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if not incident:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        incident.status = "RESOLVED"
        incident.analyst_notes = decision.notes

        action = AnalystAction(
            incident_id=incident.id,
            analyst=decision.analyst,
            action="RESOLVED",
            notes=decision.notes,
        )

        db.add(action)

        db.commit()

        return {
            "success": True,
            "incident_id": incident.incident_id,
            "status": incident.status,
            "message": "Incident resolved by analyst.",
        }

    finally:

        db.close()


# ============================================================
# METRICS
# ============================================================

@app.get("/metrics")
def get_metrics():

    db = SessionLocal()

    try:

        total_incidents = (
            db.query(Incident).count()
        )

        critical = (
            db.query(Incident)
            .filter(
                Incident.severity == "CRITICAL"
            )
            .count()
        )

        high = (
            db.query(Incident)
            .filter(
                Incident.severity == "HIGH"
            )
            .count()
        )

        active = (
            db.query(Incident)
            .filter(
                Incident.status.notin_(
                    ["RESOLVED", "FALSE_POSITIVE"]
                )
            )
            .count()
        )

        resolved = (
            db.query(Incident)
            .filter(
                Incident.status == "RESOLVED"
            )
            .count()
        )

        false_positive = (
            db.query(Incident)
            .filter(
                Incident.status == "FALSE_POSITIVE"
            )
            .count()
        )

        total_events = (
            db.query(Event).count()
        )

        return {
            "total_events": total_events,
            "total_incidents": total_incidents,
            "active_incidents": active,
            "critical_incidents": critical,
            "high_incidents": high,
            "resolved_incidents": resolved,
            "false_positive_incidents": false_positive,
        }

    finally:

        db.close()


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "service": "SentinelAI SOC Platform",
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }