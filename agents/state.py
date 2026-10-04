from __future__ import annotations

from typing import Any, Dict, List, TypedDict


class InvestigationState(TypedDict, total=False):

    # --------------------------------------------------
    # INCIDENT
    # --------------------------------------------------

    incident: Dict[str, Any]

    # --------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------

    events: List[Dict[str, Any]]
    evidence: List[str]

    # --------------------------------------------------
    # TIMELINE
    # --------------------------------------------------

    timeline: List[Dict[str, Any]]

    # --------------------------------------------------
    # RAG
    # --------------------------------------------------

    retrieved_documents: List[Dict[str, Any]]
    retrieved_context: str

    # --------------------------------------------------
    # AI ANALYSIS
    # --------------------------------------------------

    attack_hypotheses: List[str]
    investigation_summary: str

    # --------------------------------------------------
    # RISK
    # --------------------------------------------------

    risk_score: float
    severity: str
    confidence: float

    # --------------------------------------------------
    # RESPONSE
    # --------------------------------------------------

    recommended_actions: List[str]

    # --------------------------------------------------
    # HUMAN APPROVAL
    # --------------------------------------------------

    requires_human_review: bool
    analyst_decision: str
    analyst_notes: str

    # --------------------------------------------------
    # WORKFLOW
    # --------------------------------------------------

    current_step: str
    investigation_complete: bool