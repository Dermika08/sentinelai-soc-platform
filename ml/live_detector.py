import joblib
import pandas as pd


THREAT_MODEL_PATH = "models/threat_detector.joblib"
ATTACK_MODEL_PATH = "models/attack_classifier.joblib"


def load_models():
    threat_data = joblib.load(THREAT_MODEL_PATH)
    attack_data = joblib.load(ATTACK_MODEL_PATH)

    return (
        threat_data["model"],
        threat_data["features"],
        attack_data["model"],
        attack_data["features"],
    )


def clean_columns(df):
    """
    Convert raw CIC-IDS2018 column names into the
    same names used during model training.
    """

    df = df.copy()

    df.columns = (
        df.columns
        .str.strip()
        .str.replace(" ", "_", regex=False)
        .str.replace("/", "_per_", regex=False)
    )

    return df


def predict_flow(row):

    (
        threat_model,
        threat_features,
        attack_model,
        attack_features,
    ) = load_models()

    # --------------------------------------------------
    # Prepare input
    # --------------------------------------------------

    if isinstance(row, dict):
        df = pd.DataFrame([row])
    else:
        df = row.copy()

    df = clean_columns(df)

    # --------------------------------------------------
    # Validate features
    # --------------------------------------------------

    missing = [
        feature
        for feature in threat_features
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    # --------------------------------------------------
    # Threat detection
    # --------------------------------------------------

    X_threat = df[threat_features]

    threat_prediction = threat_model.predict(
        X_threat
    )[0]

    threat_probabilities = threat_model.predict_proba(
        X_threat
    )[0]

    threat_confidence = float(
        max(threat_probabilities)
    )

    if int(threat_prediction) == 1:
        threat = "Malicious"
    else:
        threat = "Benign"

    # --------------------------------------------------
    # Attack classification
    # --------------------------------------------------

    X_attack = df[attack_features]

    attack_prediction = attack_model.predict(
        X_attack
    )[0]

    attack_probabilities = attack_model.predict_proba(
        X_attack
    )[0]

    attack_confidence = float(
        max(attack_probabilities)
    )

    # --------------------------------------------------
    # Extract network evidence
    # --------------------------------------------------

    def get_value(column, default=0):
        if column in df.columns:
            return df[column].iloc[0]
        return default

    destination_port = int(
        get_value("Dst_Port", 0)
    )

    flow_duration = float(
        get_value("Flow_Duration", 0)
    )

    packet_rate = float(
        get_value("Flow_Pkts_per_s", 0)
    )

    byte_rate = float(
        get_value("Flow_Byts_per_s", 0)
    )

    forward_packets = int(
        get_value("Tot_Fwd_Pkts", 0)
    )

    backward_packets = int(
        get_value("Tot_Bwd_Pkts", 0)
    )

    # --------------------------------------------------
    # Return complete SOC result
    # --------------------------------------------------

    return {
        "threat": threat,
        "threat_confidence": threat_confidence,

        "attack_family": str(
            attack_prediction
        ),

        "attack_confidence": attack_confidence,

        "destination_port": destination_port,

        "flow_duration": flow_duration,

        "packet_rate": packet_rate,

        "byte_rate": byte_rate,

        "forward_packets": forward_packets,

        "backward_packets": backward_packets,
    }


if __name__ == "__main__":

    print("=" * 60)
    print("       SENTINELAI LIVE ML DETECTOR")
    print("=" * 60)

    threat_model, threat_features, attack_model, attack_features = load_models()

    print("\nModels loaded successfully.")

    print(
        f"Threat model features : {len(threat_features)}"
    )

    print(
        f"Attack model features : {len(attack_features)}"
    )

    print("\nThreat classes:")
    print(threat_model.classes_)

    print("\nAttack classes:")
    print(attack_model.classes_)

    print("\nDetector ready.")