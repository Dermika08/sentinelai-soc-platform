import streamlit as st
import pandas as pd
from pathlib import Path
import requests
import re
import html
import time


# ============================================================
# OPTIONAL AI IMPORTS
# ============================================================

try:
    from rag.retriever import retrieve, format_context
except Exception:
    retrieve = None
    format_context = None

try:
    from agent.llm_agent import generate_report
except Exception:
    generate_report = None


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="SentinelAI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

RESULTS_FILE = (
    BASE_DIR
    / "reports"
    / "batch_detection_results.csv"
)

API_BASE_URL = "http://127.0.0.1:8000"


# ============================================================
# SIMPLE PROFESSIONAL CSS
# ============================================================

st.markdown(
    """
    <style>

    /* Main width */
    .block-container {
        max-width: 1450px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    /* Hide Streamlit branding */
    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    /* Header */
    .hero-box {
        padding: 25px;
        border-radius: 16px;
        border: 1px solid rgba(100, 116, 139, 0.25);
        margin-bottom: 25px;
    }

    .hero-title {
        font-size: 34px;
        font-weight: 800;
        margin-bottom: 5px;
    }

    .hero-subtitle {
        font-size: 16px;
        opacity: 0.7;
    }

    .online-status {
        margin-top: 12px;
        font-size: 13px;
        font-weight: 700;
        color: #22c55e;
    }

    /* Small status text */
    .muted {
        opacity: 0.65;
        font-size: 13px;
    }

    /* Section title */
    .section-title {
        font-size: 24px;
        font-weight: 750;
        margin-top: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_value(value, default="Unknown"):
    """
    Safely convert missing values.
    """

    try:
        if pd.isna(value):
            return default
    except Exception:
        pass

    return value


def clean_ai_text(value):
    """
    Remove accidental HTML/Markdown artifacts from
    LLM-generated text before displaying it.
    """

    if value is None:
        return ""

    text = str(value)

    # Remove HTML tags
    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

    # Decode HTML entities
    text = html.unescape(text)

    # Remove repeated whitespace
    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    # Fix a few common duplicated words caused by generation
    text = re.sub(
        r"\b(\w+)\s+\1\b",
        r"\1",
        text,
        flags=re.IGNORECASE,
    )

    return text.strip()


def clean_list(items):
    """
    Clean a list returned by the LLM.
    """

    if items is None:
        return []

    if isinstance(items, str):
        items = [items]

    cleaned = []

    for item in items:

        text = clean_ai_text(item)

        if text:
            cleaned.append(text)

    return cleaned


def display_list(items, empty_message="No information available."):
    """
    Display investigation items as clean bullet points.
    """

    cleaned = clean_list(items)

    if not cleaned:
        st.info(empty_message)
        return

    for item in cleaned:

        text = str(item).strip()

        if not text:
            continue

        st.markdown(
            f"- {text}"
        )


def display_paragraphs(
    items,
    empty_message="No information available."
):
    """
    Display AI narrative content as clean paragraphs.
    """

    cleaned = clean_list(items)

    if not cleaned:
        st.info(empty_message)
        return

    for item in cleaned:

        text = str(item).strip()

        if not text:
            continue

        st.markdown(
            text
        )


# ============================================================
# BACKEND FUNCTIONS
# ============================================================

def get_incidents():

    response = requests.get(
        f"{API_BASE_URL}/api/incidents",	
        timeout=10,
    )

    response.raise_for_status()

    data = response.json()

    return data.get("incidents", [])


def get_incident(incident_id):

    response = requests.get(
        f"{API_BASE_URL}/api/incidents/{incident_id}",
        timeout=10,
    )

    response.raise_for_status()

    return response.json()


def create_recommendation(incident_id, recommendation):
    response = requests.post(
        f"{API_BASE_URL}/api/approval/recommendation",
        json={
            "incident_id": incident_id,
            "recommendation": recommendation,
        },
        timeout=10,
    )

    response.raise_for_status()
    return response.json()


def get_approval(incident_id):
    response = requests.get(
        f"{API_BASE_URL}/api/approval/{incident_id}",
        timeout=10,
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return response.json()


def approve_incident(
    incident_id,
    analyst="SOC Analyst",
    notes="",
):
    response = requests.post(
        f"{API_BASE_URL}/api/approval/{incident_id}/approve",
        json={
            "analyst": analyst,
            "notes": notes,
        },
        timeout=10,
    )

    response.raise_for_status()
    return response.json()


def reject_incident(
    incident_id,
    analyst="SOC Analyst",
    notes="",
):
    response = requests.post(
        f"{API_BASE_URL}/api/approval/{incident_id}/reject",
        json={
            "analyst": analyst,
            "notes": notes,
        },
        timeout=10,
    )

    response.raise_for_status()
    return response.json()


def simulate_response(incident_id):
    response = requests.post(
        f"{API_BASE_URL}/api/approval/{incident_id}/simulate",
        timeout=10,
    )

    response.raise_for_status()
    return response.json()
# ============================================================
# LOAD DETECTION RESULTS
# ============================================================

if not RESULTS_FILE.exists():

    st.error(
        "Batch detection results were not found."
    )

    st.info(
        "Run: python -m ml.batch_detector"
    )

    st.stop()


try:

    df = pd.read_csv(
        RESULTS_FILE
    )

except Exception as error:

    st.error(
        "Could not load detection results."
    )

    st.exception(error)

    st.stop()


# ============================================================
# BASIC DATA VALIDATION
# ============================================================

required_columns = [
    "threat",
    "risk_score",
    "attack_family",
    "attack_confidence",
    "risk_level",
    "priority",
]


missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]


if missing_columns:

    st.error(
        "Required columns are missing from "
        "batch_detection_results.csv"
    )

    st.write(
        "Missing:",
        missing_columns,
    )

    st.stop()


# ============================================================
# NUMERIC CLEANING
# ============================================================

numeric_columns = [
    "risk_score",
    "attack_confidence",
    "threat_confidence",
    "destination_port",
    "packet_rate",
    "flow_duration",
]


for column in numeric_columns:

    if column in df.columns:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        ).fillna(0)


# ============================================================
# NORMALIZE TEXT COLUMNS
# ============================================================

df["threat"] = (
    df["threat"]
    .astype(str)
    .str.strip()
)

df["attack_family"] = (
    df["attack_family"]
    .astype(str)
    .str.strip()
)

df["risk_level"] = (
    df["risk_level"]
    .astype(str)
    .str.strip()
)

df["priority"] = (
    df["priority"]
    .astype(str)
    .str.strip()
)


# ============================================================
# HEADER
# ============================================================

st.markdown("# 🛡️ SentinelAI")

st.markdown(
    "**AI-Powered Cybersecurity Incident Investigation & Response Platform**"
)

st.success("🟢 SOC DETECTION ENGINE ONLINE")

st.divider()

# ============================================================
# SECURITY OVERVIEW
# ============================================================

st.markdown(
    "## Security Operations Overview"
)

st.caption(
    "Current security activity processed by SentinelAI."
)


total_flows = len(df)


malicious = df[
    df["threat"]
    .str.upper()
    .eq("MALICIOUS")
].copy()


benign = df[
    df["threat"]
    .str.upper()
    .eq("BENIGN")
].copy()


malicious_count = len(malicious)

benign_count = len(benign)


critical_count = (
    df["priority"]
    .str.upper()
    .eq("CRITICAL")
    .sum()
)


# ============================================================
# KPI ROW
# ============================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Network Flows",
        f"{total_flows:,}",
    )


with col2:

    st.metric(
        "Malicious Detections",
        f"{malicious_count:,}",
        delta=(
            f"{malicious_count / total_flows * 100:.1f}%"
            if total_flows
            else "0%"
        ),
        delta_color="inverse",
    )


with col3:

    st.metric(
        "Critical Alerts",
        f"{critical_count:,}",
    )


with col4:

    st.metric(
        "Benign Flows",
        f"{benign_count:,}",
    )


st.divider()


# ============================================================
# SECURITY ALERT QUEUE
# ============================================================

st.markdown(
    "## 🚨 Security Alert Queue"
)

st.caption(
    "High-risk detections grouped by attack family."
)


if malicious.empty:

    st.success(
        "No malicious activity detected."
    )

else:

    grouped_alerts = (
        malicious
        .groupby("attack_family")
        .agg(
            risk_score=("risk_score", "max"),
            attack_confidence=(
                "attack_confidence",
                "max",
            ),
            event_count=(
                "attack_family",
                "size",
            ),
            risk_level=(
                "risk_level",
                "first",
            ),
        )
        .reset_index()
        .sort_values(
            "risk_score",
            ascending=False,
        )
    )


    for position, alert_group in enumerate(
        grouped_alerts.head(10).itertuples(
            index=False
        ),
        start=1,
    ):

        attack_family = (
            str(
                alert_group.attack_family
            )
        )

        risk_score = float(
            alert_group.risk_score
        )

        confidence = (
            float(
                alert_group.attack_confidence
            )
            * 100
        )

        risk_level = (
            str(
                alert_group.risk_level
            )
            .upper()
        )

        event_count = int(
            alert_group.event_count
        )


        with st.container(
            border=True
        ):

            st.markdown(
                f"### {position}. {attack_family} Detection"
            )

            st.caption(
                f"Attack family: {attack_family}"
            )


            col1, col2, col3, col4 = st.columns(4)


            with col1:

                if risk_level == "CRITICAL":

                    st.error(
                        f"🔴 {risk_level}"
                    )

                elif risk_level == "HIGH":

                    st.warning(
                        f"🟠 {risk_level}"
                    )

                elif risk_level == "MEDIUM":

                    st.info(
                        f"🟡 {risk_level}"
                    )

                else:

                    st.success(
                        f"🟢 {risk_level}"
                    )


            with col2:

                st.metric(
                    "Risk",
                    f"{risk_score:.2f}/100",
                )


            with col3:

                st.metric(
                    "Confidence",
                    f"{confidence:.2f}%",
                )


            with col4:

                st.metric(
                    "Related Events",
                    f"{event_count:,}",
                )
            st.write("")

            investigate_alert = st.button(
                f"🔎 Investigate {attack_family}",
                key=f"queue_investigate_{position}",
                use_container_width=True,
            )

            if investigate_alert:

                st.session_state["selected_attack_family"] = (
                    attack_family
                )

                st.rerun()


st.divider()


# ============================================================
# RISK SUMMARY
# ============================================================

st.markdown(
    "## Risk Summary"
)


max_risk = (
    float(df["risk_score"].max())
    if not df.empty
    else 0
)


avg_risk = (
    float(df["risk_score"].mean())
    if not df.empty
    else 0
)


avg_malicious_risk = (
    float(
        malicious["risk_score"].mean()
    )
    if not malicious.empty
    else 0
)


col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Maximum Risk",
        f"{max_risk:.2f}/100",
    )


with col2:

    st.metric(
        "Average Risk",
        f"{avg_risk:.2f}/100",
    )


with col3:

    st.metric(
        "Average Malicious Risk",
        f"{avg_malicious_risk:.2f}/100",
    )


st.divider()


# ============================================================
# ALERT INVESTIGATION
# ============================================================

st.markdown(
    "## 🔎 Alert Investigation"
)

st.caption(
    "Inspect ML evidence, risk assessment, RAG knowledge "
    "and AI-assisted investigation."
)


if malicious.empty:

    st.info(
        "There are no malicious alerts to investigate."
    )

    st.stop()


# ============================================================
# SORT MALICIOUS ALERTS
# ============================================================

malicious_sorted = (
    malicious
    .sort_values(
        "risk_score",
        ascending=False,
    )
)


options = malicious_sorted.index.tolist()


options = malicious_sorted.index.tolist()


# ------------------------------------------------------------
# SELECTED ATTACK FROM SECURITY ALERT QUEUE
# ------------------------------------------------------------

selected_attack_family = st.session_state.get(
    "selected_attack_family"
)


# If user clicked "Investigate DoS" or another queue button,
# automatically select the matching alert.
if selected_attack_family:

    matching_indices = malicious_sorted[
        malicious_sorted["attack_family"]
        .astype(str)
        .str.lower()
        .eq(
            str(selected_attack_family).lower()
        )
    ].index.tolist()

    if matching_indices:

        default_index = options.index(
            matching_indices[0]
        )

    else:

        default_index = 0

else:

    default_index = 0


selected_index = st.selectbox(
    "Select an alert",
    options,
    index=default_index,
    format_func=lambda x:
        (
            f"Row {df.loc[x, 'row']} — "
            f"{df.loc[x, 'attack_family']} — "
            f"Risk "
            f"{df.loc[x, 'risk_score']:.2f}"
        ),
)
alert = df.loc[selected_index]

# ============================================================
# FIND BACKEND INCIDENT
# ============================================================

incident_id = None

backend_incidents = []


try:

    backend_incidents = get_incidents()

except Exception:

    st.warning(
        "Backend API is not currently available. "
        "ML results can still be viewed."
    )


if backend_incidents:

    selected_attack = str(
        alert.get(
            "attack_family",
            "",
        )
    ).strip().lower()

    matching_incidents = []

    for incident in backend_incidents:

        backend_attack = str(
            incident.get(
                "attack_category",
                incident.get(
                    "category",
                    incident.get(
                        "attack_family",
                        "",
                    ),
                ),
            )
        ).strip().lower()

        if (
            selected_attack == backend_attack
            or selected_attack in backend_attack
            or backend_attack in selected_attack
        ):
            matching_incidents.append(
                incident
            )

    if matching_incidents:

        matching_incidents.sort(
            key=lambda incident:
                float(
                    incident.get(
                        "risk_score",
                        0,
                    )
                ),
            reverse=True,
        )

        incident_id = (
            matching_incidents[0]
            .get("incident_id")
        )


if incident_id:

    st.success(
        f"Backend Incident: {incident_id}"
    )

else:

    st.warning(
        "No matching backend incident found."
    )


# ============================================================
# ML DETECTION
# ============================================================

st.markdown(
    "### 🧠 ML Detection"
)


col1, col2 = st.columns(2)


with col1:

    st.write(
        "**Threat:**",
        safe_value(
            alert.get(
                "threat"
            )
        ),
    )

    st.write(
        "**Threat Confidence:**",
        f"{float(alert.get('threat_confidence', 0)):.2%}",
    )

    st.write(
        "**Attack Family:**",
        safe_value(
            alert.get(
                "attack_family"
            )
        ),
    )


with col2:

    st.write(
        "**Attack Confidence:**",
        f"{float(alert.get('attack_confidence', 0)):.2%}",
    )

    st.write(
        "**Risk Level:**",
        safe_value(
            alert.get(
                "risk_level"
            )
        ),
    )

    st.write(
        "**Priority:**",
        safe_value(
            alert.get(
                "priority"
            )
        ),
    )


# ============================================================
# RISK ASSESSMENT
# ============================================================

st.markdown(
    "### ⚠️ Risk Assessment"
)


col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Risk Score",
        f"{float(alert.get('risk_score', 0)):.2f}/100",
    )


with col2:

    st.metric(
        "Risk Level",
        str(
            alert.get(
                "risk_level",
                "UNKNOWN",
            )
        ).upper(),
    )


with col3:

    st.metric(
        "Priority",
        str(
            alert.get(
                "priority",
                "UNKNOWN",
            )
        ).upper(),
    )


# ============================================================
# NETWORK EVIDENCE
# ============================================================

st.markdown(
    "### 🌐 Network Evidence"
)


col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Destination Port",
        int(
            alert.get(
                "destination_port",
                0,
            )
        ),
    )


with col2:

    st.metric(
        "Packet Rate",
        f"{float(alert.get('packet_rate', 0)):,.2f}",
    )


with col3:

    st.metric(
        "Flow Duration",
        f"{float(alert.get('flow_duration', 0)):,.0f}",
    )


# ============================================================
# AI INVESTIGATION
# ============================================================

st.divider()

st.markdown(
    "## 🤖 AI SOC Analyst"
)

st.caption(
    "AI-assisted investigation using observed ML evidence "
    "and retrieved cybersecurity knowledge."
)


report_key = (
    f"investigation_{selected_index}"
)


if report_key not in st.session_state:

    st.session_state[
        report_key
    ] = None


# ============================================================
# INVESTIGATION BUTTON
# ============================================================

investigate = st.button(
    "🧠 Investigate Alert with AI",
    type="primary",
    use_container_width=True,
    key=f"investigate_{selected_index}",
)


if investigate:

    if retrieve is None:

        st.error(
            "RAG retriever could not be imported."
        )

    elif generate_report is None:

        st.error(
            "LLM agent could not be imported."
        )

    else:

        with st.spinner(
            "SentinelAI is investigating the alert..."
        ):

            try:

                attack_family = str(
                    alert.get(
                        "attack_family",
                        "",
                    )
                )


                # ====================================================
                # OBSERVED EVIDENCE
                # ====================================================

                evidence = [

                    (
                        f"Detected attack family: "
                        f"{attack_family}"
                    ),

                    (
                        f"Model confidence: "
                        f"{float(alert.get('attack_confidence', 0)):.2%}"
                    ),

                    (
                        f"Risk score: "
                        f"{float(alert.get('risk_score', 0)):.2f}/100"
                    ),

                    (
                        f"Risk level: "
                        f"{alert.get('risk_level', 'UNKNOWN')}"
                    ),

                    (
                        f"Destination port: "
                        f"{int(alert.get('destination_port', 0))}"
                    ),

                    (
                        f"Packet rate: "
                        f"{float(alert.get('packet_rate', 0)):,.2f}"
                    ),

                    (
                        f"Flow duration: "
                        f"{float(alert.get('flow_duration', 0)):,.0f}"
                    ),

                ]


                alert_payload = {

                    "attack_family":
                        attack_family,

                    "confidence":
                        float(
                            alert.get(
                                "attack_confidence",
                                0,
                            )
                        ),

                    "risk_score":
                        float(
                            alert.get(
                                "risk_score",
                                0,
                            )
                        ),

                    "risk_level":
                        str(
                            alert.get(
                                "risk_level",
                                "UNKNOWN",
                            )
                        ),

                    "evidence":
                        evidence,

                }


                # ====================================================
                # RAG
                # ====================================================

                rag_start = time.perf_counter()

                retrieved = retrieve(
                    attack_family
                )

                rag_time = (
                    time.perf_counter()
                    - rag_start
                )

                knowledge = format_context(
                    retrieved
                )

                # ====================================================
                # LLM
                # ====================================================

                llm_start = time.perf_counter()

                report = generate_report(
                    alert_payload,
                    knowledge,
                )

                llm_time = (
                    time.perf_counter()
                    - llm_start
                )

                # ====================================================
                # PERFORMANCE INFORMATION
                # ====================================================

                st.caption(
                    f"Investigation timing — "
                    f"RAG: {rag_time:.2f}s | "
                    f"LLM: {llm_time:.2f}s"
                )
                # --------------------------------------------
                # ADD RAG SOURCES IF MISSING
                # --------------------------------------------

                if isinstance(report, dict):

                    if not report.get(
                        "retrieved_sources"
                    ):

                        sources = []

                        for item in retrieved:

                            if isinstance(item, dict):

                                source = (
                                    item.get("source")
                                    or item.get("document")
                                    or item.get("title")
                                    or "Knowledge source"
                                )

                                sources.append(
                                    str(source)
                                )

                            else:

                                sources.append(
                                    str(item)
                                )

                        report[
                            "retrieved_sources"
                        ] = sources

                # --------------------------------------------
                # SAVE RESULT
                # --------------------------------------------

                st.session_state[
                    report_key
                ] = report

            except Exception as error:

                st.error(
                    "AI investigation failed."
                )

                st.exception(
                    error
                )
                # ====================================================
                # NORMALIZE REPORT
                # ====================================================

                if not isinstance(
                    report,
                    dict,
                ):

                    report = {
                        "summary":
                            str(report),
                        "attack_type":
                            attack_family,
                        "severity":
                            alert.get(
                                "risk_level",
                                "UNKNOWN",
                            ),
                        "confidence":
                            alert.get(
                                "attack_confidence",
                                0,
                            ),
                        "observed_evidence":
                            evidence,
                        "analysis":
                            [],
                        "investigation_plan":
                            [],
                        "recommended_actions":
                            [],
                        "retrieved_sources":
                            [],
                        "analyst_caution":
                            "",
                    }


                # ====================================================
                # SOURCE EXTRACTION
                # ====================================================

                sources = (
                    report.get(
                        "retrieved_sources"
                    )
                    or []
                )


                if not sources:

                    for item in retrieved:

                        if isinstance(
                            item,
                            dict,
                        ):

                            source = (
                                item.get(
                                    "source"
                                )
                                or item.get(
                                    "document"
                                )
                                or item.get(
                                    "title"
                                )
                                or "Cybersecurity knowledge base"
                            )

                            sources.append(
                                str(source)
                            )

                        else:

                            sources.append(
                                str(item)
                            )


                report[
                    "retrieved_sources"
                ] = sources


                # ====================================================
                # SAVE
                # ====================================================

                st.session_state[
                    report_key
                ] = report


            except Exception as error:

                st.error(
                    "AI investigation failed."
                )

                st.exception(
                    error
                )

# ============================================================
# GET GENERATED AI REPORT
# ============================================================

report = st.session_state.get(
    report_key
)


# ====================================================
# CREATE BACKEND RECOMMENDATION
# ====================================================

if incident_id and isinstance(report, dict):

    recommended_actions = report.get(
        "recommended_actions",
        []
    )

    if isinstance(
        recommended_actions,
        list
    ):

        recommendation_text = "\n".join(
            clean_ai_text(action)
            for action in recommended_actions
            if str(action).strip()
        )

    else:

        recommendation_text = clean_ai_text(
            recommended_actions
        )

    if recommendation_text.strip():

        recommendation_key = (
            f"recommendation_created_{incident_id}"
        )

        if not st.session_state.get(
            recommendation_key,
            False
        ):

            try:

                create_recommendation(
                    incident_id,
                    recommendation_text
                )

                st.session_state[
                    recommendation_key
                ] = True

            except Exception as error:

                st.warning(
                    "AI investigation completed, "
                    "but the backend recommendation "
                    "could not be created."
                )

                st.caption(
                    f"Backend error: {error}"
                )	
# ============================================================
# DISPLAY AI REPORT
# ============================================================


if report is None:

    st.info(
        "Click **Investigate Alert with AI** "
        "to run RAG retrieval and AI investigation."
    )

else:

    # ========================================================
    # SUMMARY
    # ========================================================

    st.markdown(
        "### 📋 Incident Summary"
    )

    summary = clean_ai_text(
        report.get(
            "summary",
            "No summary available.",
        )
    )

    if summary:

        st.write(summary)

    else:

        st.info(
            "No summary available."
        )


    # ========================================================
    # THREAT ASSESSMENT
    # ========================================================

    st.markdown(
        "### 🎯 Threat Assessment"
    )


    confidence = float(
        report.get(
            "confidence",
            0,
        )
    )


    if confidence <= 1:

        confidence *= 100


    col1, col2, col3 = st.columns(3)


    with col1:

        st.metric(
            "Attack Type",
            clean_ai_text(
                report.get(
                    "attack_type",
                    "Unknown",
                )
            ),
        )


    with col2:

        st.metric(
            "Severity",
            clean_ai_text(
                report.get(
                    "severity",
                    "UNKNOWN",
                )
            ).upper(),
        )


    with col3:

        st.metric(
            "AI Confidence",
            f"{confidence:.2f}%",
        )


    # ========================================================
    # OBSERVED EVIDENCE
    # ========================================================

    st.markdown(
        "### 🔍 Observed Evidence"
    )

    display_list(
        report.get(
            "observed_evidence",
            [],
        )
    )


    # ========================================================
    # AI ANALYSIS
    # ========================================================

    st.markdown(
        "### 🧠 AI Analysis"
    )

    display_paragraphs(
        report.get(
            "analysis",
            [],
        )
    )


    # ========================================================
    # INVESTIGATION PLAN
    # ========================================================

    st.markdown(
        "### 🕵️ Investigation Plan"
    )

    display_list(
        report.get(
            "investigation_plan",
            [],
        )
    )


    # ========================================================
    # RECOMMENDED RESPONSE
    # ========================================================

    st.markdown(
        "### 🛡️ Recommended Response"
    )

    display_list(
        report.get(
            "recommended_actions",
            [],
        )
    )


    # ========================================================
    # RAG SOURCES
    # ========================================================

    st.markdown(
        "### 📚 Retrieved Knowledge"
    )

    display_list(
        report.get(
            "retrieved_sources",
            [],
        )
    )


    # ========================================================
    # ANALYST CAUTION
    # ========================================================

    caution = clean_ai_text(
        report.get(
            "analyst_caution",
            "",
        )
    )


    if caution:

        st.warning(
            f"⚠️ Analyst Caution\n\n{caution}"
        )


# ========================================================
# HUMAN REVIEW
# ========================================================

st.divider()

st.markdown(
    "## 👤 Human Analyst Review"
)

st.warning(
    "SentinelAI generates recommendations only. "
    "No response action is automatically executed. "
    "Human approval is required."
)


# ========================================================
# ANALYST INFORMATION
# ========================================================

analyst_name = st.text_input(
    "Analyst Name",
    value="SOC Analyst",
    key=f"analyst_name_{selected_index}",
)


analyst_notes = st.text_area(
    "Analyst Notes",
    placeholder=(
        "Enter investigation notes, "
        "approval reason, or rejection reason."
    ),
    key=f"analyst_notes_{selected_index}",
)


# ========================================================
# ACTION BUTTONS
# ========================================================

approve_col, reject_col, simulate_col = st.columns(3)


with approve_col:

    approve_clicked = st.button(
        "✅ Approve",
        key=f"approve_{selected_index}",
        use_container_width=True,
    )


with reject_col:

    reject_clicked = st.button(
        "❌ Reject",
        key=f"reject_{selected_index}",
        use_container_width=True,
    )


with simulate_col:

    simulate_clicked = st.button(
        "🧪 Simulate Response",
        key=f"simulate_{selected_index}",
        use_container_width=True,
    )


# ========================================================
# APPROVE
# ========================================================

if approve_clicked:

    if not incident_id:

        st.error(
            "Cannot approve because no backend incident "
            "is linked to this alert."
        )

    else:

        try:

            result = approve_incident(
                incident_id,
                analyst_name,
                analyst_notes,
            )

            st.success(
                "✅ Recommendation approved by human analyst."
            )

            approval = result.get(
                "approval",
                {}
            )

            st.info(
                f"""
**Incident:** {approval.get("incident_id", incident_id)}

**Status:** {approval.get("status", "APPROVED")}

**Approved by:** {approval.get("analyst", analyst_name)}
"""
            )

            st.caption(
                "Human approval has been recorded. "
                "No real cybersecurity action was executed."
            )

        except Exception as error:

            st.error(
                "Failed to approve recommendation."
            )

            st.exception(error)


# ========================================================
# REJECT
# ========================================================

if reject_clicked:

    if not incident_id:

        st.error(
            "Cannot reject because no backend incident "
            "is linked to this alert."
        )

    else:

        try:

            result = reject_incident(
                incident_id,
                analyst_name,
                analyst_notes,
            )

            st.warning(
                "❌ Recommendation rejected by human analyst."
            )

            approval = result.get(
                "approval",
                {}
            )

            st.info(
                f"""
**Incident:** {approval.get("incident_id", incident_id)}

**Status:** {approval.get("status", "REJECTED")}

**Reviewed by:** {approval.get("analyst", analyst_name)}
"""
            )

            st.caption(
                "The recommended response was rejected. "
                "No cybersecurity action was executed."
            )

        except Exception as error:

            st.error(
                "Failed to reject recommendation."
            )

            st.exception(error)


# ========================================================
# SIMULATE RESPONSE
# ========================================================

if simulate_clicked:

    if not incident_id:

        st.error(
            "Cannot simulate response: "
            "no incident ID is available."
        )

    else:

        try:

            result = simulate_response(
                incident_id
            )

            st.success(
                "🧪 Simulated response completed successfully."
            )

            approval = result.get(
                "approval",
                {}
            )

            st.info(
                f"""
**Incident:** {approval.get("incident_id", incident_id)}

**Status:** {approval.get("status", "EXECUTION_SIMULATED")}

**Approved by:** {approval.get("analyst", "SOC Analyst")}
"""
            )

            st.caption(
                "No real cybersecurity action was executed. "
                "This was a simulated response after human approval."
            )

        except Exception as error:

            st.error(
                "Failed to simulate response."
            )

            st.exception(error)


# ========================================================
# CURRENT STATUS
# ========================================================

if incident_id:

    try:

        incident_detail = get_incident(
            incident_id
        )

        if isinstance(
            incident_detail,
            dict,
        ):

            status = (
                incident_detail.get(
                    "status"
                )
                or incident_detail.get(
                    "incident",
                    {},
                ).get(
                    "status"
                )
            )

            if status:

                st.info(
                    f"Current backend incident status: **{status}**"
                )

    except Exception:

        pass
# ============================================================
# FOOTER
# ============================================================
		
st.divider()

st.caption(
    "SentinelAI • AI-assisted cybersecurity investigation • "
    "Human approval required for response actions"
)