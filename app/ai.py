from openai import OpenAI

from config import OPENROUTER_API_KEY, MODEL_NAME
from prompts import SYSTEM_PROMPT


# ============================================================
# OPENROUTER CLIENT
# ============================================================

client = OpenAI(
    api_key=OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1",
)


# ============================================================
# AI SOC ANALYSIS
# ============================================================

def analyze_alert(context):
    """
    Send the prepared SOC incident context to the AI
    and return the generated analysis.
    """

    prompt = f"""
{SYSTEM_PROMPT}

================ INCIDENT DATA ================

{context}

================================================

Analyze the incident according to the SOC analysis
requirements provided above.

Base the analysis only on the supplied evidence.
Do not invent events or claim successful compromise
without supporting evidence.
"""

    try:

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
        )

        # ----------------------------------------------------
        # SAFELY EXTRACT RESPONSE
        # ----------------------------------------------------

        if not response.choices:
            raise RuntimeError(
                "AI provider returned no choices."
            )

        analysis = response.choices[0].message.content

        if not analysis:
            raise RuntimeError(
                "AI provider returned an empty response."
            )

        return analysis

    except Exception as error:

        print("\n========== AI ERROR ==========\n")
        print("The AI analysis request failed.")
        print(f"Error: {error}")

        return f"""
## AI Analysis Unavailable

The SOC alert, threat intelligence, risk assessment,
incident classification, and evidence assessment were
successfully processed, but the AI analysis service
did not return a valid response.

### Status

- Wazuh Alert: Processed
- Threat Intelligence: Processed
- Risk Assessment: Processed
- Incident Classification: Processed
- Evidence Assessment: Processed
- AI Analysis: Failed
- Manual Investigation: Required

### Error

{error}

The deterministic SOC assessment remains available.
"""