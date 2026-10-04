"""
SentinelAI Investigation Service

Connects incident data with:
    - cybersecurity knowledge retrieval
    - LLM investigation
    - structured investigation results

No response action is executed automatically.
"""

from __future__ import annotations

from typing import Any, Dict

from agent.llm_agent import generate_structured_report


def investigate_incident(
    incident: Dict[str, Any],
    knowledge: str = "",
) -> Dict[str, Any]:
    """
    Investigate one SentinelAI incident.

    The LLM receives only the incident evidence and
    retrieved cybersecurity knowledge.
    """

    # --------------------------------------------------------
    # BUILD ALERT PAYLOAD
    # --------------------------------------------------------

    alert = {
        "attack_family": incident.get(
            "attack_category",
            "Unknown",
        ),

        "confidence": incident.get(
            "confidence",
            0.0,
        ),

        "risk_score": incident.get(
            "risk_score",
            0.0,
        ),

        "risk_level": incident.get(
            "severity",
            "UNKNOWN",
        ),

        "evidence": incident.get(
            "evidence",
            [],
        ),
    }

    # --------------------------------------------------------
    # LLM INVESTIGATION
    # --------------------------------------------------------

    report = generate_structured_report(
        alert=alert,
        knowledge=knowledge,
    )

    # --------------------------------------------------------
    # SAFETY ENFORCEMENT
    # --------------------------------------------------------

    # Human approval must always remain required.
    report["requires_human_review"] = True

    # Never claim that an action was executed.
    report["action_status"] = "RECOMMENDATION_ONLY"

    return report


if __name__ == "__main__":

    print("=" * 70)
    print("          SENTINELAI INCIDENT INVESTIGATOR")
    print("=" * 70)

    sample_incident = {
        "incident_id": "INC-0001",
        "title": "Possible Denial-of-Service Attack",
        "attack_category": "DoS",
        "severity": "CRITICAL",
        "risk_score": 93.97,
        "confidence": 0.9991,
        "event_count": 903,
        "evidence": [
            "903 related network events were correlated.",
            "Detected attack family: DoS.",
            "Observed risk score: 93.97/100.",
            "Attack classification confidence: 99.91%.",
            "Destination port(s): 21",
        ],
    }

    knowledge = """
ATTACK TYPE: DoS

DESCRIPTION:
A denial-of-service attack attempts to make a service
or network resource unavailable.

DEFENSIVE GUIDANCE:
Monitor abnormal traffic patterns and consider
appropriate rate limiting or filtering.
"""

    print("\nInvestigating INC-0001...\n")

    result = investigate_incident(
        sample_incident,
        knowledge,
    )

    import json

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    print("\n" + "=" * 70)
    print("             INVESTIGATION COMPLETE")
    print("=" * 70)