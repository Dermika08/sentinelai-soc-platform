"""
SentinelAI Alert Correlation Engine

Groups related ML detections into meaningful security alerts
instead of treating every network flow as a separate alert.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List

import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_TIME_WINDOW_SECONDS = 300


# ============================================================
# CORRELATED ALERT
# ============================================================

@dataclass
class CorrelatedAlert:
    alert_id: str
    attack_family: str
    risk_score: float
    confidence: float
    risk_level: str
    priority: str

    event_count: int

    destination_ports: List[int]
    source_ips: List[str]
    destination_ips: List[str]

    first_seen: str
    last_seen: str

    correlation_reasons: List[str]

    events: List[Dict[str, Any]]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _unique(values: List[Any]) -> List[Any]:
    result = []

    for value in values:
        if pd.isna(value):
            continue

        if value not in result:
            result.append(value)

    return result


def _get_risk_level(risk_score: float) -> str:
    if risk_score >= 90:
        return "CRITICAL"

    if risk_score >= 70:
        return "HIGH"

    if risk_score >= 40:
        return "MEDIUM"

    if risk_score > 0:
        return "LOW"

    return "BENIGN"


def _get_priority(risk_score: float, confidence: float) -> str:
    if risk_score >= 90 or confidence >= 0.90:
        return "CRITICAL"

    if risk_score >= 70 or confidence >= 0.70:
        return "HIGH"

    if risk_score >= 40 or confidence >= 0.40:
        return "MEDIUM"

    if risk_score > 0:
        return "LOW"

    return "BENIGN"


# ============================================================
# CORRELATION ENGINE
# ============================================================

class AlertCorrelator:
    """
    Correlates related malicious events.

    Current correlation signals:

    1. Attack family
    2. Temporal proximity
    3. Destination port
    4. Source IP
    5. Destination IP

    This is intentionally rule-based and explainable.
    """

    def __init__(
        self,
        time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
    ):
        self.time_window_seconds = time_window_seconds

    # --------------------------------------------------------
    # NORMALIZE DATA
    # --------------------------------------------------------

    def normalize_events(self, df: pd.DataFrame) -> pd.DataFrame:

        if df is None or df.empty:
            return pd.DataFrame()

        data = df.copy()

        # Make sure important columns exist
        defaults = {
            "attack_family": "Unknown",
            "attack_confidence": 0.0,
            "risk_score": 0.0,
            "risk_level": "UNKNOWN",
            "priority": "UNKNOWN",
            "destination_port": 0,
            "source_ip": "Unknown",
            "destination_ip": "Unknown",
        }

        for column, default in defaults.items():

            if column not in data.columns:
                data[column] = default

        # Timestamp handling
        if "timestamp" in data.columns:

            data["timestamp"] = pd.to_datetime(
                data["timestamp"],
                errors="coerce",
            )

        else:

            data["timestamp"] = pd.NaT

        # Numeric fields
        data["attack_confidence"] = pd.to_numeric(
            data["attack_confidence"],
            errors="coerce",
        ).fillna(0.0)

        data["risk_score"] = pd.to_numeric(
            data["risk_score"],
            errors="coerce",
        ).fillna(0.0)

        data["destination_port"] = pd.to_numeric(
            data["destination_port"],
            errors="coerce",
        ).fillna(0).astype(int)

        # Remove benign events
        data = data[
            data["attack_family"]
            .astype(str)
            .str.lower()
            != "benign"
        ]

        return data.reset_index(drop=True)

    # --------------------------------------------------------
    # CORRELATE
    # --------------------------------------------------------

    def correlate(self, df: pd.DataFrame) -> List[CorrelatedAlert]:

        data = self.normalize_events(df)

        if data.empty:
            return []

        # Sort chronologically when timestamps exist
        if data["timestamp"].notna().any():

            data = data.sort_values(
                "timestamp",
                na_position="last",
            )

        groups: List[pd.DataFrame] = []

        # ----------------------------------------------------
        # GROUP BY ATTACK FAMILY
        # ----------------------------------------------------

        for attack_family, family_df in data.groupby(
            "attack_family",
            dropna=False,
        ):

            family_df = family_df.copy()

            # -----------------------------------------------
            # Split by temporal proximity
            # -----------------------------------------------

            current_group = []

            previous_time = None

            for index, row in family_df.iterrows():

                current_time = row["timestamp"]

                # First event
                if not current_group:

                    current_group.append(index)
                    previous_time = current_time
                    continue

                # If timestamps are unavailable,
                # keep same attack family together.
                if pd.isna(current_time) or pd.isna(previous_time):

                    current_group.append(index)
                    previous_time = current_time
                    continue

                difference = (
                    current_time - previous_time
                ).total_seconds()

                if difference <= self.time_window_seconds:

                    current_group.append(index)

                else:

                    groups.append(
                        family_df.loc[current_group]
                    )

                    current_group = [index]

                previous_time = current_time

            if current_group:

                groups.append(
                    family_df.loc[current_group]
                )

        # ----------------------------------------------------
        # BUILD CORRELATED ALERTS
        # ----------------------------------------------------

        alerts = []

        for number, group in enumerate(groups, start=1):

            alert = self._build_alert(
                group,
                number,
            )

            alerts.append(alert)

        # Highest risk first
        alerts.sort(
            key=lambda x: x.risk_score,
            reverse=True,
        )

        return alerts

    # --------------------------------------------------------
    # BUILD ALERT
    # --------------------------------------------------------

    def _build_alert(
        self,
        group: pd.DataFrame,
        number: int,
    ) -> CorrelatedAlert:

        attack_families = _unique(
            group["attack_family"]
            .astype(str)
            .tolist()
        )

        attack_family = (
            attack_families[0]
            if attack_families
            else "Unknown"
        )

        # ----------------------------------------------------
        # Risk
        # ----------------------------------------------------

        risk_values = [
            _safe_float(value)
            for value in group["risk_score"]
        ]

        max_risk = max(risk_values) if risk_values else 0.0

        # ----------------------------------------------------
        # Confidence
        # ----------------------------------------------------

        confidence_values = [
            _safe_float(value)
            for value in group["attack_confidence"]
        ]

        max_confidence = (
            max(confidence_values)
            if confidence_values
            else 0.0
        )

        # ----------------------------------------------------
        # Risk level
        # ----------------------------------------------------

        risk_level = _get_risk_level(max_risk)

        priority = _get_priority(
            max_risk,
            max_confidence,
        )

        # ----------------------------------------------------
        # Ports
        # ----------------------------------------------------

        ports = _unique(
            [
                _safe_int(value)
                for value in group["destination_port"]
                if _safe_int(value) != 0
            ]
        )

        # ----------------------------------------------------
        # IPs
        # ----------------------------------------------------

        source_ips = _unique(
            group["source_ip"]
            .astype(str)
            .tolist()
        )

        destination_ips = _unique(
            group["destination_ip"]
            .astype(str)
            .tolist()
        )

        # ----------------------------------------------------
        # Timestamp
        # ----------------------------------------------------

        valid_times = group["timestamp"].dropna()

        if not valid_times.empty:

            first_seen = str(valid_times.min())

            last_seen = str(valid_times.max())

        else:

            first_seen = "Unknown"
            last_seen = "Unknown"

        # ----------------------------------------------------
        # Explainable correlation reasons
        # ----------------------------------------------------

        reasons = []

        if len(group) > 1:

            reasons.append(
                f"{len(group)} events share the same attack family"
            )

        else:

            reasons.append(
                "Single malicious event detected"
            )

        if len(valid_times) > 1:

            duration = (
                valid_times.max()
                - valid_times.min()
            ).total_seconds()

            if duration <= self.time_window_seconds:

                reasons.append(
                    "Events occurred within the configured time window"
                )

        if len(ports) == 1:

            reasons.append(
                f"Events target the same destination port ({ports[0]})"
            )

        elif len(ports) > 1:

            reasons.append(
                "Events involve related destination ports"
            )

        if len(source_ips) == 1:

            reasons.append(
                "Events originate from the same source IP"
            )

        elif len(source_ips) > 1:

            reasons.append(
                f"{len(source_ips)} source IPs contributed to the activity"
            )

        if max_confidence >= 0.90:

            reasons.append(
                "High ML attack classification confidence"
            )

        if max_risk >= 90:

            reasons.append(
                "Risk score exceeds the critical threshold"
            )

        # ----------------------------------------------------
        # Event records
        # ----------------------------------------------------

        events = group.to_dict(
            orient="records"
        )

        # Convert timestamps to strings
        for event in events:

            if "timestamp" in event:

                timestamp = event["timestamp"]

                if pd.notna(timestamp):

                    event["timestamp"] = str(timestamp)

                else:

                    event["timestamp"] = None

        return CorrelatedAlert(
            alert_id=f"ALT-{number:04d}",
            attack_family=attack_family,
            risk_score=round(max_risk, 2),
            confidence=round(max_confidence, 4),
            risk_level=risk_level,
            priority=priority,
            event_count=len(group),
            destination_ports=ports,
            source_ips=source_ips,
            destination_ips=destination_ips,
            first_seen=first_seen,
            last_seen=last_seen,
            correlation_reasons=reasons,
            events=events,
        )


# ============================================================
# SIMPLE PUBLIC FUNCTION
# ============================================================

def correlate_alerts(
    df: pd.DataFrame,
    time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Convenience function used by other parts of SentinelAI.
    """

    engine = AlertCorrelator(
        time_window_seconds=time_window_seconds
    )

    alerts = engine.correlate(df)

    return [
        asdict(alert)
        for alert in alerts
    ]


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 65)
    print("          SENTINELAI ALERT CORRELATION ENGINE")
    print("=" * 65)

    input_file = "reports/batch_detection_results.csv"

    print(f"\nLoading: {input_file}")

    try:

        dataframe = pd.read_csv(input_file)

        print(
            f"Loaded {len(dataframe):,} network events."
        )

        correlator = AlertCorrelator(
            time_window_seconds=300
        )

        correlated_alerts = correlator.correlate(
            dataframe
        )

        print(
            f"\nCorrelated alerts created: "
            f"{len(correlated_alerts)}"
        )

        print("\n" + "-" * 65)

        for alert in correlated_alerts[:10]:

            print(
                f"\n{alert.alert_id}"
            )

            print(
                f"Attack Family : {alert.attack_family}"
            )

            print(
                f"Events        : {alert.event_count}"
            )

            print(
                f"Risk          : {alert.risk_score}/100"
            )

            print(
                f"Confidence    : "
                f"{alert.confidence * 100:.2f}%"
            )

            print(
                f"Risk Level    : {alert.risk_level}"
            )

            print(
                f"Priority      : {alert.priority}"
            )

            print(
                "Reasons:"
            )

            for reason in alert.correlation_reasons:

                print(
                    f"  - {reason}"
                )

        print("\n" + "=" * 65)
        print("             CORRELATION COMPLETE")
        print("=" * 65)

    except FileNotFoundError:

        print(
            f"\nERROR: Could not find {input_file}"
        )

        print(
            "Make sure batch_detection_results.csv "
            "exists inside the reports folder."
        )

    except Exception as error:

        print(
            f"\nERROR: {error}"
        )