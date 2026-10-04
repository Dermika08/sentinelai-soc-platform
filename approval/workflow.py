"""
SentinelAI Human-in-the-Loop Approval Workflow

AI recommendations are NEVER treated as executed actions.
Every recommendation must pass through analyst approval.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


# ============================================================
# APPROVAL STATES
# ============================================================

RECOMMENDATION_ONLY = "RECOMMENDATION_ONLY"
AWAITING_APPROVAL = "AWAITING_APPROVAL"
APPROVED = "APPROVED"
REJECTED = "REJECTED"
EXECUTION_SIMULATED = "EXECUTION_SIMULATED"


# ============================================================
# APPROVAL RECORD
# ============================================================

@dataclass
class ApprovalRecord:
    incident_id: str
    recommendation: str
    status: str
    analyst: Optional[str]
    analyst_notes: Optional[str]
    created_at: str
    updated_at: str


# ============================================================
# APPROVAL WORKFLOW
# ============================================================

class ApprovalWorkflow:

    def __init__(self):
        self.records = {}

    # --------------------------------------------------------
    # CREATE RECOMMENDATION
    # --------------------------------------------------------

    def create_recommendation(
        self,
        incident_id: str,
        recommendation: str,
    ) -> ApprovalRecord:

        now = datetime.now().isoformat()

        record = ApprovalRecord(
            incident_id=incident_id,
            recommendation=recommendation,
            status=AWAITING_APPROVAL,
            analyst=None,
            analyst_notes=None,
            created_at=now,
            updated_at=now,
        )

        self.records[incident_id] = record

        return record

    # --------------------------------------------------------
    # APPROVE
    # --------------------------------------------------------

    def approve(
        self,
        incident_id: str,
        analyst: str,
        notes: str = "",
    ) -> ApprovalRecord:

        if incident_id not in self.records:
            raise ValueError(
                f"No recommendation found for {incident_id}"
            )

        record = self.records[incident_id]

        record.status = APPROVED
        record.analyst = analyst
        record.analyst_notes = notes
        record.updated_at = datetime.now().isoformat()

        return record

    # --------------------------------------------------------
    # REJECT
    # --------------------------------------------------------

    def reject(
        self,
        incident_id: str,
        analyst: str,
        notes: str = "",
    ) -> ApprovalRecord:

        if incident_id not in self.records:
            raise ValueError(
                f"No recommendation found for {incident_id}"
            )

        record = self.records[incident_id]

        record.status = REJECTED
        record.analyst = analyst
        record.analyst_notes = notes
        record.updated_at = datetime.now().isoformat()

        return record

    # --------------------------------------------------------
    # SIMULATED EXECUTION
    # --------------------------------------------------------

    def simulate_execution(
        self,
        incident_id: str,
    ) -> ApprovalRecord:

        if incident_id not in self.records:
            raise ValueError(
                f"No recommendation found for {incident_id}"
            )

        record = self.records[incident_id]

        if record.status != APPROVED:
            raise PermissionError(
                "Response cannot be simulated before analyst approval."
            )

        record.status = EXECUTION_SIMULATED
        record.updated_at = datetime.now().isoformat()

        return record

    # --------------------------------------------------------
    # GET RECORD
    # --------------------------------------------------------

    def get_record(
        self,
        incident_id: str,
    ) -> Optional[ApprovalRecord]:

        return self.records.get(incident_id)

    # --------------------------------------------------------
    # EXPORT
    # --------------------------------------------------------

    def to_dict(
        self,
        incident_id: str,
    ):

        record = self.get_record(incident_id)

        if record is None:
            return None

        return asdict(record)


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 65)
    print("       SENTINELAI HUMAN-IN-THE-LOOP WORKFLOW")
    print("=" * 65)

    workflow = ApprovalWorkflow()

    # --------------------------------------------------------
    # Create recommendation
    # --------------------------------------------------------

    recommendation = workflow.create_recommendation(
        incident_id="INC-0001",
        recommendation=(
            "Monitor abnormal traffic and consider "
            "appropriate rate limiting."
        ),
    )

    print("\nRecommendation created:")
    print(recommendation)

    # --------------------------------------------------------
    # Attempt simulated execution BEFORE approval
    # --------------------------------------------------------

    print("\nTesting approval enforcement...")

    try:

        workflow.simulate_execution(
            "INC-0001"
        )

    except PermissionError as error:

        print(
            f"BLOCKED: {error}"
        )

    # --------------------------------------------------------
    # Analyst approval
    # --------------------------------------------------------

    print("\nAnalyst approving recommendation...")

    approved = workflow.approve(
        incident_id="INC-0001",
        analyst="SOC-Analyst",
        notes="Evidence reviewed. Recommendation approved.",
    )

    print(approved)

    # --------------------------------------------------------
    # Simulated execution
    # --------------------------------------------------------

    print("\nSimulating approved action...")

    executed = workflow.simulate_execution(
        "INC-0001"
    )

    print(executed)

    print("\n" + "=" * 65)
    print("             APPROVAL WORKFLOW COMPLETE")
    print("=" * 65)