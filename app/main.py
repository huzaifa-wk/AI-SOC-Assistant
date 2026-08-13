from parser import load_alert
from alert_formatter import build_alert_text
from ti_manager import get_threat_intelligence
from risk_engine import calculate_risk
from incident_classifier import classify_incident
from evidence import build_evidence
from context_builder import build_context
from ai import analyze_alert
from report import generate_report, save_report
from output import (
    print_section,
    print_risk,
    print_classification,
    print_evidence,
)


# ============================================================
# CONFIGURATION
# ============================================================

ALERT_FILE = "sample_alerts/ssh_bruteforce.json"


# ============================================================
# MAIN SOC PIPELINE
# ============================================================

def main():
    """
    Execute the complete AI SOC incident-analysis pipeline.

    Pipeline:

        Wazuh Alert
            ↓
        Alert Formatting
            ↓
        Threat Intelligence
            ↓
        Deterministic Risk Assessment
            ↓
        Incident Classification
            ↓
        Evidence Assessment
            ↓
        AI Context
            ↓
        AI SOC Analysis
            ↓
        Incident Report
    """

    # --------------------------------------------------------
    # 1. LOAD WAZUH ALERT
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

    threat_intelligence, abuse_score = get_threat_intelligence(
        source_ip
    )

    print(threat_intelligence)

    # --------------------------------------------------------
    # 4. EXTRACT RISK INPUTS
    # --------------------------------------------------------

    rule = alert.get("rule", {})

    try:
        rule_level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        rule_level = 0

    mitre = alert.get("mitre", {})
    mitre_ids = mitre.get("id", [])

    # --------------------------------------------------------
    # 5. DETERMINISTIC RISK ASSESSMENT
    # --------------------------------------------------------

    risk_assessment = calculate_risk(
        rule_level=rule_level,
        source_ip=source_ip,
        abuse_score=abuse_score,
        mitre_ids=mitre_ids,
    )

    print_risk(risk_assessment)

    # --------------------------------------------------------
    # 6. INCIDENT CLASSIFICATION
    # --------------------------------------------------------

    classification = classify_incident(alert)

    print_classification(classification)

    # --------------------------------------------------------
    # 7. EVIDENCE ASSESSMENT
    # --------------------------------------------------------

    evidence = build_evidence(
        alert=alert,
        threat_intelligence=threat_intelligence,
        risk_assessment=risk_assessment,
        classification=classification,
    )

    print_evidence(evidence)

    # --------------------------------------------------------
    # 8. BUILD AI CONTEXT
    # --------------------------------------------------------

    context = build_context(
        alert_text=alert_text,
        threat_intelligence=threat_intelligence,
        risk_assessment=risk_assessment,
        classification=classification,
        evidence=evidence,
    )

    # --------------------------------------------------------
    # 9. AI SOC ANALYSIS
    # --------------------------------------------------------

    print_section("AI SOC ANALYSIS")

    analysis = analyze_alert(context)

    print(analysis)

    # --------------------------------------------------------
    # 10. GENERATE INCIDENT REPORT
    # --------------------------------------------------------

    report = generate_report(
        context=context,
        analysis=analysis,
        risk_assessment=risk_assessment,
    )

    # --------------------------------------------------------
    # 11. SAVE INCIDENT REPORT
    # --------------------------------------------------------

    filepath = save_report(report)

    print("\nReport Saved Successfully!")
    print(f"Report Path : {filepath}")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()