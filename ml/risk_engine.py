from datetime import datetime


# Base severity for each attack family.
ATTACK_SEVERITY = {
    "Benign": 0,
    "Bot": 65,
    "DoS": 80,
    "Infiltration": 95,
    "Web Attack": 85,
}


def clamp(value, minimum=0, maximum=100):
    return max(
        minimum,
        min(maximum, value)
    )


def confidence_score(confidence):
    """
    Convert model confidence from
    0-1 into a 0-100 contribution.
    """

    return clamp(
        confidence * 100
    )


def calculate_risk(
    attack_family,
    confidence,
    packet_rate=None,
    flow_duration=None,
    destination_port=None
):

    base_score = ATTACK_SEVERITY.get(
        attack_family,
        50
    )

    confidence_component = (
        confidence_score(confidence)
        * 0.30
    )

    risk_score = (
        base_score * 0.70
        + confidence_component
    )

    evidence = []

    # -----------------------------------------
    # Traffic-based evidence
    # -----------------------------------------

    if (
        packet_rate is not None
        and packet_rate > 10000
    ):

        risk_score += 5

        evidence.append(
            "Very high packet rate detected"
        )

    if (
        flow_duration is not None
        and flow_duration < 1000
    ):

        risk_score += 3

        evidence.append(
            "Unusually short network flows"
        )

    if (
        destination_port is not None
        and destination_port in [
            21,
            22,
            23,
            25,
            53,
            80,
            443,
            3389,
        ]
    ):

        evidence.append(
            f"Traffic targets service port "
            f"{destination_port}"
        )

    risk_score = clamp(
        risk_score
    )

    # -----------------------------------------
    # Risk level
    # -----------------------------------------

    if risk_score >= 85:

        risk_level = "CRITICAL"

    elif risk_score >= 70:

        risk_level = "HIGH"

    elif risk_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # -----------------------------------------
    # Default evidence
    # -----------------------------------------

    evidence.insert(
        0,
        f"Detected attack family: "
        f"{attack_family}"
    )

    evidence.insert(
        1,
        f"Model confidence: "
        f"{confidence * 100:.2f}%"
    )

    return {
        "timestamp":
            datetime.now().isoformat(),

        "attack_family":
            attack_family,

        "confidence":
            round(confidence, 4),

        "risk_score":
            round(risk_score, 2),

        "risk_level":
            risk_level,

        "evidence":
            evidence,
    }


def print_alert(alert):

    print(
        "\n"
        + "=" * 55
    )

    print(
        "             SENTINELAI SECURITY ALERT"
    )

    print(
        "=" * 55
    )

    print(
        f"\nTimestamp    : "
        f"{alert['timestamp']}"
    )

    print(
        f"Attack       : "
        f"{alert['attack_family']}"
    )

    print(
        f"Confidence   : "
        f"{alert['confidence'] * 100:.2f}%"
    )

    print(
        f"Risk Score   : "
        f"{alert['risk_score']}/100"
    )

    print(
        f"Risk Level   : "
        f"{alert['risk_level']}"
    )

    print(
        "\nEvidence:"
    )

    for item in alert["evidence"]:

        print(
            f"  • {item}"
        )

    print(
        "\n"
        + "=" * 55
    )


if __name__ == "__main__":

    # Example alert.
    #
    # Later this information will come
    # automatically from our ML pipeline.

    alert = calculate_risk(
        attack_family="DoS",
        confidence=0.978,
        packet_rate=15000,
        flow_duration=500,
        destination_port=80,
    )

    print_alert(
        alert
    )