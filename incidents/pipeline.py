"""
SentinelAI Incident Pipeline

Connects:
    Correlation Engine
        ↓
    Incident Manager
        ↓
    Incident objects
"""

from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd

from correlation.correlator import AlertCorrelator
from incidents.incident_manager import IncidentManager


def create_incidents_from_dataframe(
    dataframe: pd.DataFrame,
    time_window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    """
    Run alert correlation and convert the resulting
    correlated alerts into SentinelAI incidents.
    """

    # --------------------------------------------------------
    # STEP 1: CORRELATION
    # --------------------------------------------------------

    correlator = AlertCorrelator(
        time_window_seconds=time_window_seconds
    )

    correlated_alerts = correlator.correlate(
        dataframe
    )

    # --------------------------------------------------------
    # STEP 2: INCIDENT CREATION
    # --------------------------------------------------------

    manager = IncidentManager()

    incidents = []

    for number, alert in enumerate(
        correlated_alerts,
        start=1,
    ):

        incident = manager.create_from_alert(
            alert,
            number,
        )

        incidents.append(incident)

    # --------------------------------------------------------
    # STEP 3: CONVERT TO DICTIONARIES
    # --------------------------------------------------------

    return manager.export_incidents()


def run_pipeline(
    input_file: str = "reports/batch_detection_results.csv",
) -> List[Dict[str, Any]]:
    """
    Complete detection → correlation → incident pipeline.
    """

    print("=" * 70)
    print("          SENTINELAI INCIDENT PIPELINE")
    print("=" * 70)

    print(
        f"\nLoading detection results:"
        f"\n{input_file}"
    )

    dataframe = pd.read_csv(
        input_file
    )

    print(
        f"\nLoaded {len(dataframe):,} "
        f"network events."
    )

    # --------------------------------------------------------
    # CREATE INCIDENTS
    # --------------------------------------------------------

    incidents = create_incidents_from_dataframe(
        dataframe
    )

    print(
        f"\nIncidents created: "
        f"{len(incidents)}"
    )

    print("\n" + "-" * 70)

    # --------------------------------------------------------
    # DISPLAY INCIDENTS
    # --------------------------------------------------------

    for incident in incidents:

        print(
            f"\n{incident['incident_id']}"
        )

        print(
            f"Title       : "
            f"{incident['title']}"
        )

        print(
            f"Category    : "
            f"{incident['attack_category']}"
        )

        print(
            f"Status      : "
            f"{incident['status']}"
        )

        print(
            f"Severity    : "
            f"{incident['severity']}"
        )

        print(
            f"Risk        : "
            f"{incident['risk_score']}/100"
        )

        print(
            f"Confidence  : "
            f"{incident['confidence'] * 100:.2f}%"
        )

        print(
            f"Events      : "
            f"{incident['event_count']}"
        )

        print(
            "Evidence:"
        )

        for evidence in incident["evidence"]:

            print(
                f"  - {evidence}"
            )

    print("\n" + "=" * 70)
    print("             INCIDENT PIPELINE COMPLETE")
    print("=" * 70)

    return incidents


if __name__ == "__main__":

    try:

        run_pipeline()

    except FileNotFoundError:

        print(
            "\nERROR: "
            "reports/batch_detection_results.csv "
            "was not found."
        )

    except Exception as error:

        print(
            f"\nERROR: {error}"
        )