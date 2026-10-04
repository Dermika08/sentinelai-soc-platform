import subprocess
import json
import re

from agent.soc_prompt import build_prompt


MODEL = "llama3.2:3b"


# ============================================================
# OLLAMA
# ============================================================

def ask_llm(prompt: str) -> str:

    result = subprocess.run(
        [
            "ollama",
            "run",
            MODEL,
        ],
        input=prompt,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:

        raise RuntimeError(
            f"Ollama failed:\n{result.stderr}"
        )

    return result.stdout.strip()


# ============================================================
# CLEAN OUTPUT
# ============================================================

def clean_output(text: str) -> str:

    if not text:
        return ""

    # Remove ANSI escape sequences
    text = re.sub(
        r"\x1b\[[0-9;?]*[ -/]*[@-~]",
        "",
        text
    )

    # Remove strange control characters
    text = "".join(
        c
        for c in text
        if c in "\n\r\t"
        or ord(c) >= 32
    )

    return text.strip()


# ============================================================
# EXTRACT SECTION
# ============================================================

def extract_section(
    text: str,
    section_name: str,
    next_sections: list
):

    pattern = rf"{re.escape(section_name)}\s*(.*?)(?=\n(?:{'|'.join(map(re.escape, next_sections))})|\Z)"

    match = re.search(
        pattern,
        text,
        flags=re.IGNORECASE | re.DOTALL
    )

    if not match:
        return ""

    return match.group(1).strip()


# ============================================================
# LIST CONVERSION
# ============================================================

def convert_to_list(text: str):
    """
    Convert LLM section text into clean individual items.

    Handles:
    - bullet points
    - numbered points
    - multiple sentences accidentally returned on one line
    - blank lines
    """

    if not text:
        return []

    # Normalize common bullet characters
    text = text.replace("•", "\n")
    text = text.replace("‣", "\n")

    lines = text.splitlines()

    results = []

    for line in lines:

        line = line.strip()

        if not line:
            continue

        # Remove markdown bullets
        line = re.sub(
            r"^[-*]\s*",
            "",
            line
        )

        # Remove numbered bullets
        line = re.sub(
            r"^\d+[\.\)]\s*",
            "",
            line
        )

        line = line.strip()

        if not line:
            continue

        # ----------------------------------------------------
        # Split accidental multiple recommendations on one line
        # ----------------------------------------------------

        parts = re.split(
            r"(?<=[.!?])\s+(?=[A-Z])",
            line
        )

        for part in parts:

            part = part.strip()

            if part:
                results.append(part)

    return results


# ============================================================
# NORMALIZE REPORT
# ============================================================

def normalize_report(
    raw_output: str,
    alert: dict
):

    raw_output = clean_output(
        raw_output
    )

    sections = [
        "INCIDENT SUMMARY",
        "THREAT ASSESSMENT",
        "KEY EVIDENCE",
        "ANALYSIS",
        "INVESTIGATION PLAN",
        "RECOMMENDED RESPONSE",
        "ANALYST CAUTION",
    ]

    summary = extract_section(
        raw_output,
        "INCIDENT SUMMARY",
        sections[1:]
    )

    threat_assessment = extract_section(
        raw_output,
        "THREAT ASSESSMENT",
        sections[2:]
    )

    key_evidence = extract_section(
        raw_output,
        "KEY EVIDENCE",
        sections[3:]
    )

    analysis = extract_section(
        raw_output,
        "ANALYSIS",
        sections[4:]
    )

    investigation = extract_section(
        raw_output,
        "INVESTIGATION PLAN",
        sections[5:]
    )

    recommendations = extract_section(
        raw_output,
        "RECOMMENDED RESPONSE",
        sections[6:]
    )

    caution = extract_section(
        raw_output,
        "ANALYST CAUTION",
        []
    )

    # --------------------------------------------------------
    # Build structured result ourselves
    # --------------------------------------------------------

    report = {

        "summary": summary
        or "No investigation summary was generated.",

        "attack_type": alert.get(
            "attack_family",
            "Unknown"
        ),

        "severity": str(
            alert.get(
                "risk_level",
                "UNKNOWN"
            )
        ).upper(),

        "confidence": float(
            alert.get(
                "confidence",
                0
            )
        ),

        "observed_evidence": (
            convert_to_list(
                key_evidence
            )
            if key_evidence
            else alert.get(
                "evidence",
                []
            )
        ),

        "analysis": convert_to_list(
            analysis
        ),

        "investigation_plan": convert_to_list(
            investigation
        ),

        "recommended_actions": convert_to_list(
            recommendations
        ),

        "analyst_caution": caution,

        "retrieved_sources": [
            "Cybersecurity knowledge base"
        ],

        "requires_human_review": True,

        # Keep the complete LLM output
        # for debugging/audit purposes.
        "raw_report": raw_output
    }

    return report


# ============================================================
# GENERATE REPORT
# ============================================================

def generate_report(
    alert: dict,
    knowledge: str
):

    prompt = build_prompt(
        alert,
        knowledge
    )

    raw_output = ask_llm(
        prompt
    )

    return normalize_report(
        raw_output,
        alert
    )

def generate_structured_report(
    alert: dict,
    knowledge: str = "",
) -> dict:
    """
    Generate a structured investigation report.

    This is a compatibility wrapper around the existing
    SentinelAI LLM report generator.
    """

    return generate_report(
        alert=alert,
        knowledge=knowledge,
    )
# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    alert = {

        "attack_family": "DoS",

        "confidence": 0.9991,

        "risk_score": 93.97,

        "risk_level": "CRITICAL",

        "evidence": [

            "Very high packet rate detected",

            "Destination port 21",

            "Flow duration of 28 seconds",

            "High attack classification confidence"

        ]
    }


    knowledge = """
ATTACK TYPE:
DoS

DESCRIPTION:
A denial-of-service attack attempts to make a service
or network resource unavailable.

INDICATORS:
- Very high packet rate
- Large number of short-duration flows
- Repeated traffic toward the same destination service

INVESTIGATION:
- Identify source IP addresses
- Check packet and byte rates
- Identify targeted service and port
- Check service degradation
- Correlate firewall and IDS logs

MITIGATION:
- Apply rate limiting
- Use network filtering
- Monitor the targeted service
"""


    print()

    print("=" * 65)

    print(
        "          SENTINELAI LLM SOC ANALYST"
    )

    print("=" * 65)

    print()

    print(
        "Generating investigation report..."
    )

    print()

    report = generate_report(
        alert,
        knowledge
    )

    print(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False
        )
    )

    print()

    print("=" * 65)

    print(
        "             REPORT COMPLETE"
    )

    print("=" * 65)