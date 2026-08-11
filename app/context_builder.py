def build_context(
    alert_text,
    threat_intelligence,
    risk_assessment,
    incident_classification
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

    context += f"""

==============================================

### INCIDENT CLASSIFICATION

Incident Type: {incident_classification['incident_type']}

Attack Category: {incident_classification['attack_category']}

Primary Technique: {incident_classification['primary_technique']}

Protocol: {incident_classification['protocol']}

==============================================

### SOC ANALYSIS INSTRUCTIONS

Analyze this incident using the evidence
provided above.

Important rules:

- Treat Wazuh data as observed evidence.
- Treat threat intelligence as supporting evidence.
- Treat the Risk Engine assessment as the deterministic
  baseline risk assessment.
- Treat the Incident Classification as the deterministic
  classification of the observed behavior.
- Do not change the deterministic risk score.
- Do not claim successful compromise unless evidence
  confirms it.
- Clearly separate confirmed facts from interpretations
  and unconfirmed possibilities.
- Respect the Incident Status and Confidence values.
- Explain why the incident was classified this way.
- Provide investigation steps.
- Provide appropriate remediation.
- Maintain a professional SOC analyst perspective.

"""

    return context