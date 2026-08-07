def build_context(alert_text, threat_intelligence):

    context = f"""
================ INCIDENT CONTEXT ================

### WAZUH ALERT

{alert_text}

==============================================

### THREAT INTELLIGENCE

{threat_intelligence}

==============================================

Please analyze this incident like a professional SOC Analyst.

"""

    return context