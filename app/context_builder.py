def build_context(
    alert_text,
    threat_intelligence,
    risk_assessment
):

    context = f"""
================ INCIDENT CONTEXT ================

### WAZUH ALERT

{alert_text}

==============================================

### THREAT INTELLIGENCE

{threat_intelligence}

==============================================

### RISK ASSESSMENT

Risk Score: {risk_assessment['score']}/100

Risk Level: {risk_assessment['level']}

Incident Status: {risk_assessment['status']}

Confidence: {risk_assessment['confidence']}

Risk Factors:

"""

    for factor in risk_assessment["factors"]:
        context += f"- {factor}\n"

    context += """

==============================================

### SOC ANALYSIS INSTRUCTIONS

Analyze the incident using the Wazuh alert,
threat intelligence, and deterministic risk
assessment provided above.

Important:

- Do not treat the risk score as proof of compromise.
- Clearly separate confirmed evidence from assumptions.
- Do not claim successful compromise unless the
  provided evidence confirms it.
- Consider whether the source is internal or external.
- Respect the Incident Status and Confidence values.
- Explain why the risk level was assigned.
- Provide investigation steps and remediation.
- Maintain a professional SOC analyst perspective.

"""

    return context