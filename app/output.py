def print_section(title):
    """Print a consistent console section header."""

    print(f"\n========== {title} ==========\n")


def print_alert(alert_text):
    """Display the formatted Wazuh alert."""

    print_section("WAZUH ALERT")
    print(alert_text)


def print_risk(risk):
    """Display the deterministic SOC risk assessment."""

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
    """Display the incident classification."""

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
    """Display the evidence assessment."""

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


def print_ai_analysis_start():
    """Display the AI analysis section header."""

    print_section("AI SOC ANALYSIS")


def print_ai_analysis(analysis):
    """Display the AI SOC analysis."""

    print(analysis)


def print_report_saved(filepath):
    """Display the saved report path."""

    print("\nReport Saved Successfully!")
    print(f"Report Path : {filepath}")