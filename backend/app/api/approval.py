"""
SentinelAI Approval API

Human-in-the-loop response approval.

IMPORTANT:
AI recommendations are never executed automatically.
An analyst must explicitly approve a recommendation before
simulated execution is allowed.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from approval.workflow import (
    ApprovalWorkflow,
    AWAITING_APPROVAL,
    APPROVED,
    REJECTED,
    EXECUTION_SIMULATED,
)

router = APIRouter(
    prefix="/approval",
    tags=["Human Approval"],
)

# ------------------------------------------------------------
# In-memory workflow store
# ------------------------------------------------------------

workflow = ApprovalWorkflow()


# ------------------------------------------------------------
# Request schemas
# ------------------------------------------------------------

class RecommendationRequest(BaseModel):
    incident_id: str
    recommendation: str


class AnalystDecisionRequest(BaseModel):
    analyst: str
    notes: Optional[str] = ""


# ------------------------------------------------------------
# CREATE RECOMMENDATION
# ------------------------------------------------------------

@router.post("/recommendation")
def create_recommendation(
    request: RecommendationRequest,
):
    """
    Create an AI-generated recommendation.

    The recommendation starts in AWAITING_APPROVAL state.
    """

    record = workflow.create_recommendation(
        incident_id=request.incident_id,
        recommendation=request.recommendation,
    )

    return {
        "message": "Recommendation created.",
        "approval": workflow.to_dict(
            request.incident_id
        ),
    }


# ------------------------------------------------------------
# GET APPROVAL STATUS
# ------------------------------------------------------------

@router.get("/{incident_id}")
def get_approval(
    incident_id: str,
):
    """
    Get the current approval state for an incident.
    """

    record = workflow.get_record(
        incident_id
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="No recommendation found for this incident.",
        )

    return workflow.to_dict(
        incident_id
    )


# ------------------------------------------------------------
# APPROVE
# ------------------------------------------------------------

@router.post("/{incident_id}/approve")
def approve_recommendation(
    incident_id: str,
    request: AnalystDecisionRequest,
):
    """
    Analyst approves the recommendation.
    """

    try:

        record = workflow.approve(
            incident_id=incident_id,
            analyst=request.analyst,
            notes=request.notes or "",
        )

        return {
            "message": "Recommendation approved by analyst.",
            "approval": workflow.to_dict(
                incident_id
            ),
        }

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


# ------------------------------------------------------------
# REJECT
# ------------------------------------------------------------

@router.post("/{incident_id}/reject")
def reject_recommendation(
    incident_id: str,
    request: AnalystDecisionRequest,
):
    """
    Analyst rejects the recommendation.
    """

    try:

        record = workflow.reject(
            incident_id=incident_id,
            analyst=request.analyst,
            notes=request.notes or "",
        )

        return {
            "message": "Recommendation rejected by analyst.",
            "approval": workflow.to_dict(
                incident_id
            ),
        }

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


# ------------------------------------------------------------
# SIMULATED EXECUTION
# ------------------------------------------------------------

@router.post("/{incident_id}/simulate")
def simulate_response(
    incident_id: str,
):
    """
    Simulate the approved response.

    This endpoint NEVER performs a real cybersecurity action.
    It only demonstrates the approval gate.
    """

    try:

        record = workflow.simulate_execution(
            incident_id
        )

        return {
            "message": (
                "Response simulation completed "
                "after analyst approval."
            ),
            "approval": workflow.to_dict(
                incident_id
            ),
        }

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )

    except PermissionError as error:

        raise HTTPException(
            status_code=403,
            detail=str(error),
        )