from parser import load_alert
from alert_formatter import build_alert_text
from ti_manager import get_threat_intelligence
from risk_engine import calculate_risk
from incident_classifier import classify_incident
from evidence import build_evidence
from context_builder import build_context
from ai import analyze_alert
from report import generate_report, save_report


# ============================================================
# CONFIGURATION
# ============================================================

ALERT_FILE = "sample_alerts/ssh_bruteforce.json"


# ============================================================
# CONSOLE OUTPUT
# ============================================================

def print_section(title):
    """Print a consistent console section header."""

    print(f"\n========== {title} ==========\n")


def print_risk(risk):
    """Display the deterministic risk assessment."""

    print_section("RISK ASSESSMENT")

    print(f"Risk Score : {risk.get('score', 0)}/100")
    print(f"Risk Level : {risk.get('level', 'UNKNOWN')}")
    print(f"Incident Status : {risk.get('status', 'UNKNOWN')}")
    print(f"Confidence : {risk.get('confidence', 'UNKNOWN')}")

    factors = risk.get("factors", [])

    if factors:
        print("\nRisk Factors:")

        for factor in factors:
            print(f"- {factor}")


def print_classification(classification):
    """Display incident classification."""

    print_section("INCIDENT CLASSIFICATION")

    print(
        f"Incident Type : "
        f"{classification.get('incident_type', 'UNKNOWN')}"
    )

    print(
        f"Attack Category : "
        f"{classification.get('attack_category', 'UNKNOWN')}"
    )

    print(
        f"Primary Technique : "
        f"{classification.get('primary_technique', 'UNKNOWN')}"
    )

    print(
        f"Protocol : "
        f"{classification.get('protocol', 'UNKNOWN')}"
    )


def print_evidence(evidence):
    """Display evidence assessment."""

    print_section("EVIDENCE ASSESSMENT")

    print("Confirmed Evidence:")

    for item in evidence.get("confirmed", []):
        print(f"- {item}")

    print("\nSuspicious Observations:")

    for item in evidence.get("suspicious", []):
        print(f"- {item}")

    print("\nUnconfirmed:")

    for item in evidence.get("unconfirmed", []):
        print(f"- {item}")


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    # --------------------------------------------------------
    # 1. LOAD ALERT
    # --------------------------------------------------------

    alert = load_alert(ALERT_FILE)

    # --------------------------------------------------------
    # 2. FORMAT ALERT
    # --------------------------------------------------------

    alert_text = build_alert_text(alert)

    print_section("WAZUH ALERT")
    print(alert_text)

    # --------------------------------------------------------
    # 3. THREAT INTELLIGENCE
    # --------------------------------------------------------

    source_ip = alert.get("srcip", "")

    threat_intelligence, abuse_score = (
        get_threat_intelligence(source_ip)
    )

    print(threat_intelligence)

    # --------------------------------------------------------
    # 4. EXTRACT RISK DATA
    # --------------------------------------------------------

    rule = alert.get("rule", {})

    try:
        rule_level = int(
            rule.get("level", 0)
        )
    except (TypeError, ValueError):
        rule_level = 0

    mitre_ids = alert.get(
        "mitre",
        {}
    ).get(
        "id",
        []
    )

    # --------------------------------------------------------
    # 5. RISK ASSESSMENT
    # --------------------------------------------------------

    risk_assessment = calculate_risk(
        rule_level,
        source_ip,
        abuse_score,
        mitre_ids
    )

    print_risk(risk_assessment)

    # --------------------------------------------------------
    # 6. INCIDENT CLASSIFICATION
    # --------------------------------------------------------

    classification = classify_incident(
        alert
    )

    print_classification(
        classification
    )

    # --------------------------------------------------------
    # 7. EVIDENCE ASSESSMENT
    # --------------------------------------------------------

    evidence = build_evidence(
        alert,
        threat_intelligence,
        risk_assessment,
        classification
    )

    print_evidence(
        evidence
    )

    # --------------------------------------------------------
    # 8. BUILD AI CONTEXT
    # --------------------------------------------------------

    context = build_context(
        alert_text,
        threat_intelligence,
        risk_assessment,
        classification,
        evidence
    )

    # --------------------------------------------------------
    # 9. AI ANALYSIS
    # --------------------------------------------------------

    print_section("AI SOC ANALYSIS")

    analysis = analyze_alert(
        context
    )

    print(analysis)

    # --------------------------------------------------------
    # 10. GENERATE REPORT
    # --------------------------------------------------------

    report = generate_report(
        context,
        analysis
    )

    # --------------------------------------------------------
    # 11. SAVE REPORT
    # --------------------------------------------------------

    filepath = save_report(
        report
    )

    print("\nReport Saved Successfully!")
    print(filepath)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()