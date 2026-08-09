def build_context(alert_text, threat_intelligence):

    context = f"""
================ SOC INCIDENT CONTEXT ================

### WAZUH ALERT

{alert_text}

=======================================================

### THREAT INTELLIGENCE

{threat_intelligence}

=======================================================

### ANALYSIS REQUIREMENTS

Use the Wazuh alert and Threat Intelligence together.

Do not treat the alert alone as proof of compromise.

Do not treat a public IP as malicious simply because it
generated authentication failures.

If the source is an internal/private IP, recommend verifying
the asset owner and whether the activity was authorized.

If Threat Intelligence conflicts with the observed behavior,
explicitly mention the conflict.

Clearly distinguish:
- Observed evidence
- Assessment
- Possible explanations
- Confirmed compromise

=======================================================

Analyze this incident as a professional SOC Analyst.

"""
    
    return context