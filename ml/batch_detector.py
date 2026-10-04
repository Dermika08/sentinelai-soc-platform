import pandas as pd
import joblib
from ml.risk_engine import calculate_risk

INPUT_FILE = (
    "data/raw/"
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
)

OUTPUT_FILE = "reports/batch_detection_results.csv"


def main():

    print("=" * 65)
    print("        SENTINELAI FAST BATCH DETECTOR")
    print("=" * 65)

    # --------------------------------------------------
    # LOAD MODELS
    # --------------------------------------------------

    print("\nLoading models...")

    threat_bundle = joblib.load(
        "models/threat_detector.joblib"
    )

    attack_bundle = joblib.load(
        "models/attack_classifier.joblib"
    )

    threat_model = threat_bundle["model"]
    threat_features = threat_bundle["features"]

    attack_model = attack_bundle["model"]
    attack_features = attack_bundle["features"]

    print("Models loaded.")

    # --------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------

    print("\nLoading 1,000 network flows...")

    df = pd.read_csv(
        INPUT_FILE,
        nrows=1000
    )

    print(f"Loaded {len(df):,} flows.")

    # Normalize CICFlowMeter column names
    df.columns = (
        df.columns
        .str.strip()
        .str.replace(" ", "_", regex=False)
        .str.replace("/", "_per_", regex=False)
    )

    print("Column names normalized.")

    # --------------------------------------------------
    # PREPARE FEATURES
    # --------------------------------------------------

    X_threat = df[threat_features].copy()
    X_attack = df[attack_features].copy()

    X_threat = (
        X_threat
        .replace([float("inf"), float("-inf")], 0)
        .fillna(0)
    )

    X_attack = (
        X_attack
        .replace([float("inf"), float("-inf")], 0)
        .fillna(0)
    )

    # --------------------------------------------------
    # THREAT DETECTION
    # --------------------------------------------------

    print("\nRunning threat detection...")

    threat_predictions = threat_model.predict(
        X_threat
    )

    threat_probabilities = threat_model.predict_proba(
        X_threat
    )

    threat_confidence = (
        threat_probabilities.max(axis=1)
    )

    # --------------------------------------------------
    # ATTACK CLASSIFICATION
    # --------------------------------------------------

    print("Running attack classification...")

    malicious_mask = (
        threat_predictions == 1
    )

    attack_predictions = [
        "Benign"
    ] * len(df)

    attack_confidences = [
        0.0
    ] * len(df)

    if malicious_mask.any():

        malicious_features = X_attack[
            malicious_mask
        ]

        attack_pred = attack_model.predict(
            malicious_features
        )

        attack_prob = attack_model.predict_proba(
            malicious_features
        )

        attack_conf = (
            attack_prob.max(axis=1)
        )

        positions = (
            malicious_mask.nonzero()[0]
        )

        for i, position in enumerate(positions):

            attack_predictions[position] = (
                attack_pred[i]
            )

            attack_confidences[position] = (
                attack_conf[i]
            )

    # --------------------------------------------------
    # BUILD RESULTS
    # --------------------------------------------------

    results = pd.DataFrame({

        "row":
            range(len(df)),

        "dataset_label":
            df["Label"].values,

        "threat": [
            "Malicious"
            if x == 1
            else "Benign"
            for x in threat_predictions
        ],

        "threat_confidence":
            threat_confidence,

        "attack_family":
            attack_predictions,

        "attack_confidence":
            attack_confidences,

        "destination_port":
            df["Dst_Port"].values,

        "flow_duration":
            df["Flow_Duration"].values,

        "packet_rate":
            df["Flow_Pkts_per_s"].values,

        "byte_rate":
            df["Flow_Byts_per_s"].values,

        "forward_packets":
            df["Tot_Fwd_Pkts"].values,

        "backward_packets":
            df["Tot_Bwd_Pkts"].values
    })

    # --------------------------------------------------
    # RISK ENGINE
    # --------------------------------------------------

    print("\nCalculating risk scores...")

    risk_scores = []
    risk_levels = []

    for _, row in results.iterrows():

        if row["threat"] == "Benign":

            risk_scores.append(0.0)
            risk_levels.append("BENIGN")

            continue

        risk = calculate_risk(
            row["attack_family"],
            row["attack_confidence"],
            row["packet_rate"],
            row["flow_duration"],
            row["destination_port"]
        )

        risk_scores.append(
            risk["risk_score"]
        )

        risk_levels.append(
            risk["risk_level"]
        )

    results["risk_score"] = risk_scores
    results["risk_level"] = risk_levels

    # --------------------------------------------------
    # PRIORITY
    # --------------------------------------------------

    def assign_priority(row):

        if row["threat"] == "Benign":
            return "BENIGN"

        if row["risk_score"] >= 80:
            return "CRITICAL"

        if row["risk_score"] >= 60:
            return "HIGH"

        if row["risk_score"] >= 30:
            return "MEDIUM"

        return "LOW"

    results["priority"] = results.apply(
        assign_priority,
        axis=1
    )

    # --------------------------------------------------
    # SUMMARY
    # --------------------------------------------------

    print("\n")
    print("=" * 65)
    print("              BATCH RESULTS")
    print("=" * 65)

    print(
        f"\nTotal flows analyzed : "
        f"{len(results):,}"
    )

    print("\nThreat distribution:")

    print(
        results["threat"]
        .value_counts()
        .to_string()
    )

    print("\nAttack distribution:")

    malicious = results[
        results["threat"] == "Malicious"
    ]

    if len(malicious) > 0:

        print(
            malicious["attack_family"]
            .value_counts()
            .to_string()
        )

    else:

        print("No malicious traffic detected.")

    print("\nPriority distribution:")

    print(
        results["priority"]
        .value_counts()
        .to_string()
    )

    # --------------------------------------------------
    # TOP ALERTS
    # --------------------------------------------------

    if len(malicious) > 0:

        print("\nTop 10 alerts:")

        top = (
            malicious
            .sort_values(
                "risk_score",
                ascending=False
            )
            .head(10)
        )

        print(
            top[
                [
                    "row",
                    "dataset_label",
                    "attack_family",
                    "attack_confidence",
                    "risk_score",
                    "risk_level",
                    "destination_port",
                    "packet_rate",
                    "priority"
                ]
            ].to_string(
                index=False
            )
        )

    # --------------------------------------------------
    # SAVE
    # --------------------------------------------------

    results.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"\nResults saved to:"
        f"\n{OUTPUT_FILE}"
    )

    print("\n")
    print("=" * 65)
    print("          BATCH DETECTION COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    main()