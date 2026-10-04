"""
SentinelAI Incident Manager

Creates incidents from correlated alerts and persists them
to the PostgreSQL database.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from database.session import SessionLocal
from database.models import Incident as DBIncident


# ============================================================
# INCIDENT STATUSES
# ============================================================

NEW = "NEW"
INVESTIGATING = "INVESTIGATING"
AWAITING_APPROVAL = "AWAITING_APPROVAL"
APPROVED = "APPROVED"
REJECTED = "REJECTED"
RESOLVED = "RESOLVED"
FALSE_POSITIVE = "FALSE_POSITIVE"


# ============================================================
# IN-MEMORY INCIDENT MODEL
# ============================================================

@dataclass
class Incident:
    incident_id: str
    title: str
    status: str
    severity: str
    confidence: float
    attack_category: str
    risk_score: float
    event_count: int

    first_seen: str
    last_seen: str

    destination_ports: List[int]
    source_ips: List[str]
    destination_ips: List[str]

    correlation_reasons: List[str]
    evidence: List[str]

    investigation: Optional[Dict[str, Any]]
    recommended_actions: List[str]

    human_approval: Optional[str]
    analyst_notes: str

    created_at: str
    updated_at: str


# ============================================================
# INCIDENT MANAGER
# ============================================================

class IncidentManager:

    def __init__(self):
        self.incidents: Dict[str, Incident] = {}

    # ========================================================
    # SAFE DATETIME CONVERSION
    # ========================================================

    def _safe_datetime(
        self,
        value: Any,
    ) -> Optional[datetime]:

        if value is None:
            return None

        if isinstance(value, datetime):
            return value

        value_str = str(value).strip()

        if not value_str:
            return None

        if value_str.lower() in {
            "unknown",
            "none",
            "null",
            "nan",
            "nat",
        }:
            return None

        # Try pandas-style timestamp conversion
        try:
            import pandas as pd

            parsed = pd.to_datetime(
                value_str,
                errors="coerce",
            )

            if pd.isna(parsed):
                return None

            return parsed.to_pydatetime()

        except Exception:
            return None

    # ========================================================
    # CREATE INCIDENT
    # ========================================================

    def create_from_alert(
        self,
        alert: Any,
        incident_number: int,
    ) -> Incident:

        incident_id = f"INC-{incident_number:04d}"

        attack_category = getattr(
            alert,
            "attack_family",
            "Unknown",
        )

        severity = getattr(
            alert,
            "risk_level",
            "UNKNOWN",
        )

        confidence = float(
            getattr(
                alert,
                "confidence",
                0.0,
            )
        )

        risk_score = float(
            getattr(
                alert,
                "risk_score",
                0.0,
            )
        )

        event_count = int(
            getattr(
                alert,
                "event_count",
                0,
            )
        )

        title = self._generate_title(
            attack_category
        )

        raw_first_seen = getattr(
            alert,
            "first_seen",
            None,
        )

        raw_last_seen = getattr(
            alert,
            "last_seen",
            None,
        )

        first_seen_dt = self._safe_datetime(
            raw_first_seen
        )

        last_seen_dt = self._safe_datetime(
            raw_last_seen
        )

        first_seen = (
            first_seen_dt.isoformat()
            if first_seen_dt
            else "Unknown"
        )

        last_seen = (
            last_seen_dt.isoformat()
            if last_seen_dt
            else "Unknown"
        )

        evidence = self._build_evidence(
            alert
        )

        destination_ports = list(
            getattr(
                alert,
                "destination_ports",
                [],
            )
            or []
        )

        source_ips = list(
            getattr(
                alert,
                "source_ips",
                [],
            )
            or []
        )

        destination_ips = list(
            getattr(
                alert,
                "destination_ips",
                [],
            )
            or []
        )

        correlation_reasons = list(
            getattr(
                alert,
                "correlation_reasons",
                [],
            )
            or []
        )

        now = datetime.utcnow()

        # ====================================================
        # CREATE IN-MEMORY INCIDENT
        # ====================================================

        incident = Incident(
            incident_id=incident_id,

            title=title,

            status=NEW,

            severity=severity,

            confidence=confidence,

            attack_category=attack_category,

            risk_score=risk_score,

            event_count=event_count,

            first_seen=first_seen,

            last_seen=last_seen,

            destination_ports=destination_ports,

            source_ips=source_ips,

            destination_ips=destination_ips,

            correlation_reasons=correlation_reasons,

            evidence=evidence,

            investigation=None,

            recommended_actions=[],

            human_approval=None,

            analyst_notes="",

            created_at=now.isoformat(),

            updated_at=now.isoformat(),
        )

        self.incidents[
            incident_id
        ] = incident

        # ====================================================
        # SAVE TO POSTGRESQL
        # ====================================================

        self._save_to_database(
            incident,
            first_seen_dt,
            last_seen_dt,
        )

        return incident

    # ========================================================
    # SAVE INCIDENT TO DATABASE
    # ========================================================

    def _save_to_database(
        self,
        incident: Incident,
        first_seen: Optional[datetime],
        last_seen: Optional[datetime],
    ) -> None:

        db = SessionLocal()

        try:

            # Check whether incident already exists
            existing = (
                db.query(DBIncident)
                .filter(
                    DBIncident.incident_id
                    == incident.incident_id
                )
                .first()
            )

            if existing:

                existing.title = incident.title
                existing.status = incident.status
                existing.severity = incident.severity
                existing.confidence = incident.confidence
                existing.risk_score = incident.risk_score
                existing.attack_category = (
                    incident.attack_category
                )
                existing.first_seen = first_seen
                existing.last_seen = last_seen
                existing.event_count = incident.event_count
                existing.source_ips = (
                    incident.source_ips
                )
                existing.destination_ips = (
                    incident.destination_ips
                )

                db.commit()

                print(
                    f"Database incident updated: "
                    f"{incident.incident_id}"
                )

                return

            db_incident = DBIncident(

                incident_id=incident.incident_id,

                title=incident.title,

                status=incident.status,

                severity=incident.severity,

                confidence=incident.confidence,

                risk_score=incident.risk_score,

                attack_category=(
                    incident.attack_category
                ),

                first_seen=first_seen,

                last_seen=last_seen,

                event_count=incident.event_count,

                affected_users=[],

                affected_assets=[],

                source_ips=incident.source_ips,

                destination_ips=(
                    incident.destination_ips
                ),

                analyst_notes=None,
            )

            db.add(
                db_incident
            )

            db.commit()

            db.refresh(
                db_incident
            )

            print(
                f"Database incident created: "
                f"{incident.incident_id}"
            )

        except Exception:

            db.rollback()

            raise

        finally:

            db.close()

    # ========================================================
    # CREATE MULTIPLE INCIDENTS
    # ========================================================

    def create_from_alerts(
        self,
        alerts: List[Any],
    ) -> List[Incident]:

        incidents = []

        for number, alert in enumerate(
            alerts,
            start=1,
        ):

            incident = self.create_from_alert(
                alert,
                number,
            )

            incidents.append(
                incident
            )

        return incidents

    # ========================================================
    # INCIDENT TITLE
    # ========================================================

    def _generate_title(
        self,
        attack_category: str,
    ) -> str:

        titles = {

            "DoS":
                "Possible Denial-of-Service Attack",

            "DDoS":
                "Possible Distributed Denial-of-Service Attack",

            "Infiltration":
                "Possible Network Infiltration",

            "Brute Force":
                "Possible Brute-Force Attack",

            "Bot":
                "Possible Bot Activity",

            "Web Attack":
                "Possible Web Attack",
        }

        return titles.get(
            attack_category,
            f"Possible {attack_category} Security Incident",
        )

    # ========================================================
    # BUILD EVIDENCE
    # ========================================================

    def _build_evidence(
        self,
        alert: Any,
    ) -> List[str]:

        evidence = []

        event_count = int(
            getattr(
                alert,
                "event_count",
                0,
            )
        )

        risk_score = float(
            getattr(
                alert,
                "risk_score",
                0.0,
            )
        )

        confidence = float(
            getattr(
                alert,
                "confidence",
                0.0,
            )
        )

        attack_family = getattr(
            alert,
            "attack_family",
            "Unknown",
        )

        ports = getattr(
            alert,
            "destination_ports",
            [],
        )

        if event_count > 1:

            evidence.append(
                f"{event_count} related network "
                f"events were correlated."
            )

        else:

            evidence.append(
                "A single suspicious network "
                "event was detected."
            )

        evidence.append(
            f"Detected attack family: "
            f"{attack_family}."
        )

        evidence.append(
            f"Observed risk score: "
            f"{risk_score:.2f}/100."
        )

        evidence.append(
            f"Attack classification confidence: "
            f"{confidence * 100:.2f}%."
        )

        if ports:

            evidence.append(
                "Destination port(s): "
                + ", ".join(
                    str(port)
                    for port in ports
                )
            )

        return evidence

    # ========================================================
    # UPDATE STATUS
    # ========================================================

    def update_status(
        self,
        incident_id: str,
        status: str,
    ) -> Incident:

        if incident_id not in self.incidents:

            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        valid_statuses = {
            NEW,
            INVESTIGATING,
            AWAITING_APPROVAL,
            APPROVED,
            REJECTED,
            RESOLVED,
            FALSE_POSITIVE,
        }

        if status not in valid_statuses:

            raise ValueError(
                f"Invalid incident status: {status}"
            )

        incident = self.incidents[
            incident_id
        ]

        incident.status = status

        self._update_database(
            incident
        )

        return incident

    # ========================================================
    # ATTACH AI INVESTIGATION
    # ========================================================

    def attach_investigation(
        self,
        incident_id: str,
        investigation: Dict[str, Any],
    ) -> Incident:

        if incident_id not in self.incidents:

            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        incident = self.incidents[
            incident_id
        ]

        incident.investigation = investigation

        incident.recommended_actions = (
            investigation.get(
                "recommended_actions",
                [],
            )
        )

        incident.status = (
            AWAITING_APPROVAL
        )

        self._update_database(
            incident
        )

        return incident

    # ========================================================
    # APPROVE
    # ========================================================

    def approve(
        self,
        incident_id: str,
        analyst_notes: str = "",
    ) -> Incident:

        if incident_id not in self.incidents:

            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        incident = self.incidents[
            incident_id
        ]

        incident.human_approval = "APPROVED"

        incident.analyst_notes = analyst_notes

        incident.status = APPROVED

        self._update_database(
            incident
        )

        return incident

    # ========================================================
    # REJECT
    # ========================================================

    def reject(
        self,
        incident_id: str,
        analyst_notes: str = "",
    ) -> Incident:

        if incident_id not in self.incidents:

            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        incident = self.incidents[
            incident_id
        ]

        incident.human_approval = "REJECTED"

        incident.analyst_notes = analyst_notes

        incident.status = REJECTED

        self._update_database(
            incident
        )

        return incident

    # ========================================================
    # FALSE POSITIVE
    # ========================================================

    def mark_false_positive(
        self,
        incident_id: str,
        analyst_notes: str = "",
    ) -> Incident:

        if incident_id not in self.incidents:

            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        incident = self.incidents[
            incident_id
        ]

        incident.human_approval = (
            "FALSE_POSITIVE"
        )

        incident.analyst_notes = analyst_notes

        incident.status = FALSE_POSITIVE

        self._update_database(
            incident
        )

        return incident

    # ========================================================
    # RESOLVE
    # ========================================================

    def resolve(
        self,
        incident_id: str,
        analyst_notes: str = "",
    ) -> Incident:

        if incident_id not in self.incidents:

            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        incident = self.incidents[
            incident_id
        ]

        incident.status = RESOLVED

        if analyst_notes:

            incident.analyst_notes = (
                analyst_notes
            )

        self._update_database(
            incident
        )

        return incident

    # ========================================================
    # UPDATE DATABASE
    # ========================================================

    def _update_database(
        self,
        incident: Incident,
    ) -> None:

        db = SessionLocal()

        try:

            db_incident = (
                db.query(DBIncident)
                .filter(
                    DBIncident.incident_id
                    == incident.incident_id
                )
                .first()
            )

            if not db_incident:
                return

            db_incident.status = (
                incident.status
            )

            db_incident.severity = (
                incident.severity
            )

            db_incident.confidence = (
                incident.confidence
            )

            db_incident.risk_score = (
                incident.risk_score
            )

            db_incident.analyst_notes = (
                incident.analyst_notes
                or None
            )

            db.commit()

        except Exception:

            db.rollback()

            raise

        finally:

            db.close()

    # ========================================================
    # GET ONE INCIDENT
    # ========================================================

    def get_incident(
        self,
        incident_id: str,
    ) -> Incident:

        if incident_id not in self.incidents:

            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        return self.incidents[
            incident_id
        ]

    # ========================================================
    # GET ALL INCIDENTS
    # ========================================================

    def get_all_incidents(
        self,
    ) -> List[Incident]:

        return list(
            self.incidents.values()
        )

    # ========================================================
    # EXPORT
    # ========================================================

    def export_incidents(
        self,
    ) -> List[Dict[str, Any]]:

        return [
            asdict(incident)
            for incident
            in self.incidents.values()
        ]