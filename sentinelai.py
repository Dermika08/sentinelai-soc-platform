import pandas as pd

from ml.live_detector import predict_flow
from ml.risk_engine import calculate_risk
from rag.retriever import retrieve, format_context
from agent.llm_agent import generate_report


DATASET = "data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"

# Pick one real network-flow row
ROW_NUMBER = 500


def main():

    print("\n")
    print("=" * 65)
    print("                 SENTINELAI")
    print("          AI-POWERED SECURITY SOC")
    print("=" * 65)

    # ==================================================
    # STEP 1 — LOAD REAL NETWORK FLOW
    # ==================================================

    print("\n[1] REAL NETWORK TRAFFIC")
    print("-" * 65)

    df = pd.read_csv(
        DATASET,
        skiprows=lambda x: x != 0 and x != ROW_NUMBER + 1,
    )

    if len(df) == 0:
        raise RuntimeError("Could not load the selected network flow.")

    row = df.iloc[[0]]

    print(f"Dataset : {DATASET}")
    print(f"Flow row: {ROW_NUMBER}")

    if "Label" in row.columns:
        print(f"Dataset label: {row['Label'].iloc[0]}")

    # ==================================================
    # STEP 2 — REAL ML DETECTION
    # ==================================================

    print("\n[2] ML DETECTION")
    print("-" * 65)

    prediction = predict_flow(row)

    print(
        f"Threat          : {prediction['threat']}"
    )

    print(
        f"Threat Confidence: "
        f"{prediction['threat_confidence'] * 100:.2f}%"
    )

    print(
        f"Attack Family   : "
        f"{prediction['attack_family']}"
    )

    print(
        f"Attack Confidence: "
        f"{prediction['attack_confidence'] * 100:.2f}%"
    )

    # ==================================================
    # STEP 3 — RISK ASSESSMENT
    # ==================================================

    print("\n[3] RISK ASSESSMENT")
    print("-" * 65)

    alert = calculate_risk(
        attack_family=prediction["attack_family"],
        confidence=prediction["attack_confidence"],
        packet_rate=prediction["packet_rate"],
        flow_duration=prediction["flow_duration"],
        destination_port=prediction["destination_port"],
    )

    print(
        f"Risk Score : {alert['risk_score']}/100"
    )

    print(
        f"Risk Level : {alert['risk_level']}"
    )

    # ==================================================
    # STEP 4 — RAG KNOWLEDGE RETRIEVAL
    # ==================================================

    print("\n[4] RAG KNOWLEDGE RETRIEVAL")
    print("-" * 65)

    knowledge_results = retrieve(
        prediction["attack_family"]
    )

    print(
        f"Documents Retrieved : "
        f"{len(knowledge_results)}"
    )

    knowledge_context = format_context(
        knowledge_results
    )

    # ==================================================
    # STEP 5 — LLM SOC ANALYST
    # ==================================================

    print("\n[5] LLM SOC ANALYST")
    print("-" * 65)

    print("Generating investigation report...\n")

    report = generate_report(
        alert,
        knowledge_context
    )

    print(report)

    # ==================================================
    # FINAL
    # ==================================================

    print("\n")
    print("=" * 65)
    print("             SENTINELAI ANALYSIS COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    main()