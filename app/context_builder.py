def build_context(
    alert_text,
    threat_intelligence,
    risk_assessment,
    classification,
    evidence
):
    """
    Build the complete evidence-based context
    for the AI SOC analyst.
    """

    # ========================================================
    # EVIDENCE SECTIONS
    # ========================================================

    confirmed_text = "\n".join(
        f"- {item}"
        for item in evidence.get("confirmed", [])
    )

    suspicious_text = "\n".join(
        f"- {item}"
        for item in evidence.get("suspicious", [])
    )

    unconfirmed_text = "\n".join(
        f"- {item}"
        for item in evidence.get("unconfirmed", [])
    )

    # ========================================================
    # INCIDENT CONTEXT
    # ========================================================

    return f"""
================ INCIDENT CONTEXT ================

### WAZUH ALERT

{alert_text}

===================================================

### THREAT INTELLIGENCE

{threat_intelligence}

===================================================

### RISK ASSESSMENT

Risk Score:
{risk_assessment.get("score", "UNKNOWN")}/100

Risk Level:
{risk_assessment.get("level", "UNKNOWN")}

Incident Status:
{risk_assessment.get("status", "UNKNOWN")}

Confidence:
{risk_assessment.get("confidence", "UNKNOWN")}

===================================================

### INCIDENT CLASSIFICATION

Incident Type:
{classification.get("incident_type", "UNKNOWN")}

Attack Category:
{classification.get("attack_category", "UNKNOWN")}

Primary Technique:
{classification.get("primary_technique", "UNKNOWN")}

Protocol:
{classification.get("protocol", "UNKNOWN")}

===================================================

### CONFIRMED EVIDENCE

{confirmed_text}

===================================================

### SUSPICIOUS OBSERVATIONS

{suspicious_text}

===================================================

### UNCONFIRMED

{unconfirmed_text}

===================================================

### SOC ANALYSIS REQUIREMENTS

Analyze this incident as a professional SOC analyst.

IMPORTANT:

1. Clearly separate confirmed facts from interpretations.
2. Do not claim compromise unless the provided evidence confirms it.
3. Do not claim successful authentication unless it is present in the evidence.
4. Do not claim lateral movement unless there is evidence of lateral movement.
5. Do not treat the absence of threat intelligence as proof that an IP is safe.
6. Respect the deterministic risk assessment and incident classification.
7. Explain why the incident is suspicious, benign, or confirmed malicious.
8. Recommend investigation steps based only on the available evidence.
9. Do not invent usernames, processes, malware, commands, or events.
10. If threat intelligence conflicts with observed behavior, explicitly explain
    the conflict instead of ignoring either source.
11. Distinguish between an ATT&CK technique being associated with an alert
    and evidence that the technique successfully occurred.
12. Base the final conclusion on the supplied evidence, not assumptions.

===================================================
"""