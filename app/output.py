def print_alert(alert_text):

    print("\n========== WAZUH ALERT ==========\n")
    print(alert_text)


def print_risk_assessment(risk):

    print("\n========== RISK ASSESSMENT ==========\n")

    print(
        f"Risk Score : "
        f"{risk.get('score', 0)}/100"
    )

    print(
        f"Risk Level : "
        f"{risk.get('level', 'UNKNOWN')}"
    )

    print(
        f"Incident Status : "
        f"{risk.get('status', 'UNKNOWN')}"
    )

    print(
        f"Confidence : "
        f"{risk.get('confidence', 'UNKNOWN')}"
    )

    factors = risk.get("factors", [])

    if factors:

        print("\nRisk Factors:\n")

        for factor in factors:
            print(f"- {factor}")


def print_classification(classification):

    print(
        "\n========== INCIDENT CLASSIFICATION ==========\n"
    )

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

    print(
        "\n========== EVIDENCE ASSESSMENT ==========\n"
    )

    print("Confirmed Evidence:\n")

    for item in evidence.get("confirmed", []):
        print(f"- {item}")

    print("\nSuspicious Observations:\n")

    for item in evidence.get("suspicious", []):
        print(f"- {item}")

    print("\nUnconfirmed:\n")

    for item in evidence.get("unconfirmed", []):
        print(f"- {item}")


def print_ai_analysis_start():

    print("\n========== AI SOC ANALYSIS ==========\n")


def print_ai_analysis(analysis):

    print(analysis)


def print_report_saved(filepath):

    print(
        "\nReport Saved Successfully!\n"
        f"{filepath}"
    )