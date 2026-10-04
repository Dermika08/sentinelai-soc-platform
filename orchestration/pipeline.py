"""
SentinelAI End-to-End Investigation Orchestrator

Pipeline:

Detection Results
        ↓
Alert Correlation
        ↓
Incident Creation
        ↓
PostgreSQL Persistence
        ↓
RAG Knowledge Retrieval
        ↓
LLM Investigation
        ↓
Response Recommendation
        ↓
Human Approval
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from correlation.correlator import AlertCorrelator
from rag.retriever import retrieve, format_context
from agent.llm_agent import generate_structured_report
from approval.workflow import ApprovalWorkflow
from incidents.incident_manager import IncidentManager

from database.session import SessionLocal
from database.models import Incident as IncidentDB
from database.models import Investigation as InvestigationDB
from database.models import Recommendation as RecommendationDB


# ============================================================
# CONFIGURATION
# ============================================================

DETECTION_FILE = Path(
    "reports/batch_detection_results.csv"
)


# ============================================================
# SENTINELAI ORCHESTRATOR
# ============================================================

class SentinelPipeline:

    def __init__(self):

        self.correlator = AlertCorrelator(
            time_window_seconds=300
        )

        self.approval_workflow = ApprovalWorkflow()

        self.incident_manager = IncidentManager()

    # --------------------------------------------------------
    # LOAD DETECTIONS
    # --------------------------------------------------------

    def load_detections(self) -> pd.DataFrame:

        if not DETECTION_FILE.exists():

            raise FileNotFoundError(
                f"Detection file not found: {DETECTION_FILE}"
            )

        return pd.read_csv(
            DETECTION_FILE
        )

    # --------------------------------------------------------
    # CORRELATION
    # --------------------------------------------------------

    def correlate(
        self,
        dataframe: pd.DataFrame,
    ):

        return self.correlator.correlate(
            dataframe
        )

    # --------------------------------------------------------
    # SAVE INCIDENT TO POSTGRESQL
    # --------------------------------------------------------

    def save_incident_to_database(
        self,
        incident,
    ):

        db = SessionLocal()

        try:

            # ------------------------------------------------
            # Check whether incident already exists
            # ------------------------------------------------

            existing = (
                db.query(IncidentDB)
                .filter(
                    IncidentDB.incident_id
                    == incident.incident_id
                )
                .first()
            )

            if existing:

                print(
                    f"Database: "
                    f"{incident.incident_id} already exists."
                )

                return existing

            # ------------------------------------------------
            # Convert timestamp strings safely
            # ------------------------------------------------

            first_seen = self._parse_datetime(
                incident.first_seen
            )

            last_seen = self._parse_datetime(
                incident.last_seen
            )

            # ------------------------------------------------
            # Create database incident
            # ------------------------------------------------

            db_incident = IncidentDB(

                incident_id=incident.incident_id,

                title=incident.title,

                status=incident.status,

                severity=incident.severity,

                confidence=incident.confidence,

                risk_score=incident.risk_score,

                attack_category=incident.attack_category,

                first_seen=first_seen,

                last_seen=last_seen,

                event_count=incident.event_count,

                affected_users=[],

                affected_assets=[],

                source_ips=incident.source_ips,

                destination_ips=incident.destination_ips,

                analyst_notes=incident.analyst_notes,
            )

            db.add(
                db_incident
            )

            db.commit()

            db.refresh(
                db_incident
            )

            print(
                f"Database: saved "
                f"{db_incident.incident_id} "
                f"(ID={db_incident.id})"
            )

            return db_incident

        except Exception:

            db.rollback()

            raise

        finally:

            db.close()

    # --------------------------------------------------------
    # SAFE DATETIME CONVERSION
    # --------------------------------------------------------

    def _parse_datetime(
        self,
        value,
    ):

        if value is None:

            return None

        if isinstance(
            value,
            pd.Timestamp
        ):

            return value.to_pydatetime()

        text = str(
            value
        ).strip()

        if not text:

            return None

        if text.lower() in {
            "unknown",
            "nan",
            "none",
            "nat",
        }:

            return None

        try:

            parsed = pd.to_datetime(
                text,
                errors="coerce"
            )

            if pd.isna(parsed):

                return None

            return parsed.to_pydatetime()

        except Exception:

            return None

    # --------------------------------------------------------
    # RAG RETRIEVAL
    # --------------------------------------------------------

    def retrieve_knowledge(
        self,
        attack_family: str,
    ) -> str:

        results = retrieve(
            attack_family
        )

        return format_context(
            results
        )

    # --------------------------------------------------------
    # CONVERT CORRELATED ALERT TO LLM INPUT
    # --------------------------------------------------------

    def build_incident_alert(
        self,
        alert,
    ) -> Dict[str, Any]:

        evidence = list(
            alert.correlation_reasons
        )

        evidence.append(
            f"Related event count: {alert.event_count}"
        )

        if alert.destination_ports:

            evidence.append(
                "Destination ports: "
                + ", ".join(
                    str(port)
                    for port in alert.destination_ports
                )
            )

        return {

            "alert_id":
                alert.alert_id,

            "attack_family":
                alert.attack_family,

            "risk_score":
                alert.risk_score,

            "risk_level":
                alert.risk_level,

            "priority":
                alert.priority,

            "confidence":
                alert.confidence,

            "event_count":
                alert.event_count,

            "destination_ports":
                alert.destination_ports,

            "source_ips":
                alert.source_ips,

            "destination_ips":
                alert.destination_ips,

            "first_seen":
                alert.first_seen,

            "last_seen":
                alert.last_seen,

            "evidence":
                evidence,
        }

    # --------------------------------------------------------
    # INVESTIGATE ONE ALERT
    # --------------------------------------------------------

    def investigate_alert(
        self,
        alert,
        incident_id: str,
    ) -> Dict[str, Any]:

        incident_alert = (
            self.build_incident_alert(
                alert
            )
        )

        # ====================================================
        # RAG
        # ====================================================

        print(
            "\nRetrieving cybersecurity knowledge..."
        )

        knowledge = (
            self.retrieve_knowledge(
                alert.attack_family
            )
        )

        # ====================================================
        # LLM INVESTIGATION
        # ====================================================

        print(
            "Running AI investigation..."
        )

        report = generate_structured_report(
            incident_alert,
            knowledge,
        )

        # ====================================================
        # RESPONSE RECOMMENDATION
        # ====================================================

        recommendations = report.get(
            "recommended_actions",
            []
        )

        if not recommendations:

            recommendation_text = (
                "No response recommendation was generated. "
                "Additional analyst investigation is required."
            )

        else:

            recommendation_text = "\n".join(
                f"- {action}"
                for action in recommendations
            )

        # ====================================================
        # HUMAN APPROVAL
        # ====================================================

        approval = (
            self.approval_workflow
            .create_recommendation(
                incident_id=incident_id,
                recommendation=recommendation_text,
            )
        )

        return {

            "incident_id":
                incident_id,

            "alert":
                incident_alert,

            "knowledge":
                knowledge,

            "investigation":
                report,

            "approval": {

                "status":
                    approval.status,

                "analyst":
                    approval.analyst,

                "analyst_notes":
                    approval.analyst_notes,
            },
        }

    # --------------------------------------------------------
    # SAVE INVESTIGATION
    # --------------------------------------------------------

    def save_investigation_to_database(
        self,
        db_incident,
        report,
    ):

        db = SessionLocal()

        try:

            investigation = InvestigationDB(

                incident_id=db_incident.id,

                summary=report.get(
                    "summary"
                ),

                attack_type=report.get(
                    "attack_type"
                ),

                severity=report.get(
                    "severity"
                ),

                confidence=report.get(
                    "confidence"
                ),

                analysis=report.get(
                    "reasoning",
                    report.get(
                        "analysis",
                        []
                    )
                ),

                investigation_plan=report.get(
                    "investigation_plan",
                    []
                ),

                retrieved_sources=report.get(
                    "retrieved_sources",
                    []
                ),

                requires_human_review=report.get(
                    "requires_human_review",
                    True
                ),
            )

            db.add(
                investigation
            )

            db.commit()

            print(
                f"Database: investigation saved "
                f"for {db_incident.incident_id}"
            )

        except Exception:

            db.rollback()

            raise

        finally:

            db.close()

    # --------------------------------------------------------
    # SAVE RECOMMENDATION
    # --------------------------------------------------------

    def save_recommendation_to_database(
        self,
        db_incident,
        recommendation_text,
    ):

        db = SessionLocal()

        try:

            recommendation = RecommendationDB(

                incident_id=db_incident.id,

                recommendation=recommendation_text,

                status="AWAITING_APPROVAL",

            )

            db.add(
                recommendation
            )

            db.commit()

            print(
                f"Database: recommendation saved "
                f"for {db_incident.incident_id}"
            )

        except Exception:

            db.rollback()

            raise

        finally:

            db.close()

    # --------------------------------------------------------
    # RUN
    # --------------------------------------------------------

    def run(
        self,
        max_incidents: int = 10,
    ) -> List[Dict[str, Any]]:

        print("=" * 70)

        print(
            "          SENTINELAI END-TO-END PIPELINE"
        )

        print("=" * 70)

        # ====================================================
        # STEP 1 — LOAD DATA
        # ====================================================

        print(
            f"\nLoading detection results:"
            f"\n{DETECTION_FILE}"
        )

        dataframe = (
            self.load_detections()
        )

        print(
            f"\nLoaded {len(dataframe):,} "
            f"network events."
        )

        # ====================================================
        # STEP 2 — CORRELATION
        # ====================================================

        print(
            "\nRunning alert correlation..."
        )

        alerts = self.correlate(
            dataframe
        )

        print(
            f"Correlated alerts: "
            f"{len(alerts)}"
        )

        # ====================================================
        # STEP 3 — CREATE INCIDENT MANAGER
        # ====================================================

        results = []

        for index, alert in enumerate(
            alerts[:max_incidents],
            start=1,
        ):

            incident_id = (
                f"INC-{index:04d}"
            )

            print(
                "\n" + "-" * 70
            )

            print(
                f"Investigating {incident_id}..."
            )

            print(
                f"Attack Family : "
                f"{alert.attack_family}"
            )

            print(
                f"Events        : "
                f"{alert.event_count}"
            )

            print(
                f"Risk          : "
                f"{alert.risk_score}/100"
            )

            print(
                f"Confidence    : "
                f"{alert.confidence * 100:.2f}%"
            )

            # ------------------------------------------------
            # Create in-memory incident
            # ------------------------------------------------

            incident = (
                self.incident_manager
                .create_from_alert(
                    alert,
                    index,
                )
            )

            # ------------------------------------------------
            # Save incident to PostgreSQL
            # ------------------------------------------------

            db_incident = (
                self.save_incident_to_database(
                    incident
                )
            )

            # ------------------------------------------------
            # Run AI investigation
            # ------------------------------------------------

            result = (
                self.investigate_alert(
                    alert,
                    incident_id,
                )
            )

            results.append(
                result
            )

            report = (
                result["investigation"]
            )

            # ------------------------------------------------
            # Save investigation
            # ------------------------------------------------

            self.save_investigation_to_database(
                db_incident,
                report,
            )

            # ------------------------------------------------
            # Save recommendation
            # ------------------------------------------------

            recommendations = (
                report.get(
                    "recommended_actions",
                    []
                )
            )

            if recommendations:

                recommendation_text = "\n".join(
                    f"- {action}"
                    for action in recommendations
                )

            else:

                recommendation_text = (
                    "No response recommendation was generated. "
                    "Additional analyst investigation is required."
                )

            self.save_recommendation_to_database(
                db_incident,
                recommendation_text,
            )

            # ------------------------------------------------
            # Display investigation
            # ------------------------------------------------

            print(
                "\nInvestigation Summary:"
            )

            print(
                report.get(
                    "summary",
                    "No summary available."
                )
            )

            print(
                "\nSeverity:"
            )

            print(
                report.get(
                    "severity",
                    "UNKNOWN"
                )
            )

            print(
                "\nRecommended Response:"
            )

            if recommendations:

                for action in recommendations:

                    print(
                        f"  - {action}"
                    )

            else:

                print(
                    "  No response recommendation."
                )

            # ------------------------------------------------
            # Approval state
            # ------------------------------------------------

            print(
                "\nHuman Approval:"
            )

            print(
                result["approval"]["status"]
            )

        # ====================================================
        # COMPLETE
        # ====================================================

        print(
            "\n" + "=" * 70
        )

        print(
            "          SENTINELAI PIPELINE COMPLETE"
        )

        print(
            "=" * 70
        )

        return results


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    try:

        pipeline = SentinelPipeline()

        results = pipeline.run(
            max_incidents=2
        )

        print(
            f"\nProcessed incidents: "
            f"{len(results)}"
        )

    except FileNotFoundError as error:

        print(
            f"\nERROR: {error}"
        )

    except Exception as error:

        print(
            "\nPIPELINE ERROR:"
        )

        print(
            f"{type(error).__name__}: {error}"
        )