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

    This context separates:
        - Confirmed evidence
        - Suspicious observations
        - Unconfirmed possibilities

    The deterministic risk engine and incident
    classification are provided as structured inputs.
    """

    # ========================================================
    # SAFE DEFAULTS
    # ========================================================

    if not isinstance(risk_assessment, dict):
        risk_assessment = {}

    if not isinstance(classification, dict):
        classification = {}

    if not isinstance(evidence, dict):
        evidence = {}

    # ========================================================
    # EVIDENCE SECTIONS
    # ========================================================

    confirmed_items = evidence.get(
        "confirmed",
        []
    )

    suspicious_items = evidence.get(
        "suspicious",
        []
    )

    unconfirmed_items = evidence.get(
        "unconfirmed",
        []
    )

    if not isinstance(confirmed_items, list):
        confirmed_items = []

    if not isinstance(suspicious_items, list):
        suspicious_items = []

    if not isinstance(unconfirmed_items, list):
        unconfirmed_items = []

    confirmed_text = "\n".join(
        f"- {item}"
        for item in confirmed_items
    ) or "- No confirmed evidence provided."

    suspicious_text = "\n".join(
        f"- {item}"
        for item in suspicious_items
    ) or "- No suspicious observations provided."

    unconfirmed_text = "\n".join(
        f"- {item}"
        for item in unconfirmed_items
    ) or "- No unconfirmed items provided."

    # ========================================================
    # INCIDENT CONTEXT
    # ========================================================

    context = f"""
================ INCIDENT CONTEXT ================

### WAZUH ALERT

{alert_text}

===================================================

### THREAT INTELLIGENCE

{threat_intelligence}

===================================================

### DETERMINISTIC RISK ASSESSMENT

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

1. Clearly separate confirmed facts from reasonable interpretations
   and unconfirmed possibilities.

2. Do not claim compromise unless the supplied evidence confirms it.

3. Do not claim successful authentication unless successful
   authentication is explicitly present in the evidence.

4. Do not claim lateral movement unless there is direct evidence
   supporting lateral movement.

5. Do not treat the absence of threat intelligence as proof that
   an IP address is safe.

6. Consider threat intelligence when assessing the incident.

7. If threat intelligence conflicts with the observed Wazuh behavior,
   explicitly describe the conflict and consider both sources.

8. Respect the deterministic risk assessment and incident classification,
   but do not treat either one as proof of compromise.

9. Treat MITRE ATT&CK mappings as technique classifications,
   not proof that the technique was successfully executed.

10. Explain why the incident is suspicious, likely benign,
    confirmed malicious, or inconclusive based on the evidence.

11. Recommend investigation steps based only on available evidence.

12. Do not invent usernames, processes, malware, commands,
    successful logins, network activity, or other events.

13. For private/internal IP addresses, consider legitimate administrative
    activity, authorized security scanning, testing, or a potentially
    compromised internal host as possible explanations.

14. Do not overstate confidence.

15. If the available evidence is insufficient to establish compromise,
    explicitly state:

    "Evidence is insufficient to confirm compromise."

16. The final conclusion must be based on supplied evidence,
    not assumptions or external information.

===================================================
"""

    return context.strip()