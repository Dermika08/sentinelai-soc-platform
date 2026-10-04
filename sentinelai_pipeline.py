import json

from ml.risk_engine import calculate_risk
from rag.retriever import retrieve, format_context


def build_alert():

    # Simulated ML prediction.
    #
    # Later this will come directly from
    # threat_detector + attack_classifier.

    return {
        "attack_family": "DoS",
        "confidence": 0.978,
        "packet_rate": 15000,
        "flow_duration": 500,
        "destination_port": 80,
    }


def main():

    print("\n")
    print("=" * 65)
    print("                 SENTINELAI")
    print("          AI-POWERED SECURITY SOC")
    print("=" * 65)

    # --------------------------------------------------
    # STEP 1 — Receive ML detection
    # --------------------------------------------------

    alert_input = build_alert()

    print("\n[1] ML DETECTION")
    print("-" * 65)

    print(
        f"Attack Family : "
        f"{alert_input['attack_family']}"
    )

    print(
        f"Confidence    : "
        f"{alert_input['confidence'] * 100:.2f}%"
    )

    # --------------------------------------------------
    # STEP 2 — Risk Engine
    # --------------------------------------------------

    print("\n[2] RISK ASSESSMENT")
    print("-" * 65)

    alert = calculate_risk(
        attack_family=
            alert_input["attack_family"],

        confidence=
            alert_input["confidence"],

        packet_rate=
            alert_input["packet_rate"],

        flow_duration=
            alert_input["flow_duration"],

        destination_port=
            alert_input["destination_port"],
    )

    print(
        f"Risk Score : "
        f"{alert['risk_score']}/100"
    )

    print(
        f"Risk Level : "
        f"{alert['risk_level']}"
    )

    # --------------------------------------------------
    # STEP 3 — RAG retrieval
    # --------------------------------------------------

    print("\n[3] RAG KNOWLEDGE RETRIEVAL")
    print("-" * 65)

    results = retrieve(
        alert_input["attack_family"]
    )

    print(
        f"Documents Retrieved : "
        f"{len(results)}"
    )

    # --------------------------------------------------
    # STEP 4 — Build investigation context
    # --------------------------------------------------

    print("\n[4] SOC INVESTIGATION CONTEXT")
    print("-" * 65)

    context = format_context(
        results
    )

    print(context)

    # --------------------------------------------------
    # STEP 5 — Final structured alert
    # --------------------------------------------------

    final_alert = {
        "alert": alert,
        "retrieved_knowledge": results,
    }

    print("\n")
    print("=" * 65)
    print("             SENTINELAI ALERT READY")
    print("=" * 65)

    print(
        json.dumps(
            final_alert,
            indent=2
        )
    )


if __name__ == "__main__":

    main()