from openai import OpenAI

from config import OPENROUTER_API_KEY, MODEL_NAME
from prompts import SYSTEM_PROMPT


# ============================================================
# OPENROUTER CONFIGURATION
# ============================================================

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


# ============================================================
# OPENROUTER CLIENT
# ============================================================

client = OpenAI(
    api_key=OPENROUTER_API_KEY,
    base_url=OPENROUTER_BASE_URL,
    timeout=60.0,
)


# ============================================================
# AI SOC ANALYSIS
# ============================================================

def analyze_alert(context):
    """
    Send the prepared SOC incident context to the AI
    and return the generated analysis.

    The AI is responsible for interpreting and explaining
    the supplied evidence.

    It is NOT responsible for:
        - Deterministic risk scoring
        - Incident classification
        - Threat-intelligence lookup
        - Evidence generation
        - Confirming compromise without evidence
    """

    # ========================================================
    # VALIDATE CONTEXT
    # ========================================================

    if not isinstance(context, str):
        context = str(context)

    context = context.strip()

    if not context:
        return """
## AI Analysis Unavailable

No incident context was supplied to the AI analysis engine.

### Status

- Incident Context: Missing
- AI Analysis: Skipped
- Manual Investigation: Required

The deterministic SOC assessment remains available.
""".strip()

    # ========================================================
    # VALIDATE API CONFIGURATION
    # ========================================================

    if not OPENROUTER_API_KEY:

        print(
            "\n========== AI ERROR ==========\n"
        )

        print(
            "OPENROUTER_API_KEY is not configured."
        )

        return """
## AI Analysis Unavailable

The OpenRouter API key is not configured.

### Status

- Wazuh Alert: Processed
- Threat Intelligence: Processed
- Risk Assessment: Processed
- Incident Classification: Processed
- Evidence Assessment: Processed
- AI Analysis: Failed
- Manual Investigation: Required

The deterministic SOC assessment remains available.
""".strip()

    # ========================================================
    # BUILD AI PROMPT
    # ========================================================

    prompt = f"""
{SYSTEM_PROMPT}

================ INCIDENT DATA ================

{context}

================================================

Analyze the incident according to the SOC analysis
requirements provided above.

IMPORTANT:

- Use ONLY the supplied incident evidence.
- Clearly distinguish facts from interpretations.
- Do not invent events.
- Do not invent usernames, malware, processes,
  commands, successful logins, or network activity.
- Do not claim successful compromise without evidence.
- Do not treat MITRE mappings as proof of execution.
- Consider threat intelligence together with Wazuh evidence.
- Respect the deterministic risk assessment.
- Do not replace the deterministic risk score with your own score.
- If evidence is insufficient, explicitly state:
  "Evidence is insufficient to confirm compromise."

================================================
"""

    # ========================================================
    # REQUEST AI ANALYSIS
    # ========================================================

    try:

        response = client.chat.completions.create(
            model=MODEL_NAME,

            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": context,
                },
            ],

            temperature=0.2,
        )

        # ====================================================
        # VALIDATE RESPONSE
        # ====================================================

        if not response:

            raise RuntimeError(
                "AI provider returned no response."
            )

        if not response.choices:

            raise RuntimeError(
                "AI provider returned no choices."
            )

        message = response.choices[0].message

        if not message:

            raise RuntimeError(
                "AI provider returned an empty message."
            )

        analysis = message.content

        if not isinstance(
            analysis,
            str
        ):

            raise RuntimeError(
                "AI provider returned an invalid response format."
            )

        analysis = analysis.strip()

        if not analysis:

            raise RuntimeError(
                "AI provider returned an empty analysis."
            )

        return analysis

    # ========================================================
    # AI/API FAILURE
    # ========================================================

    except Exception as error:

        print(
            "\n========== AI ERROR ==========\n"
        )

        print(
            "The AI analysis request failed."
        )

        print(
            f"Error: {error}"
        )

        return f"""
## AI Analysis Unavailable

The SOC alert, threat intelligence, deterministic
risk assessment, incident classification, and evidence
assessment were successfully processed, but the AI
analysis service did not return a valid response.

### Status

- Wazuh Alert: Processed
- Threat Intelligence: Processed
- Risk Assessment: Processed
- Incident Classification: Processed
- Evidence Assessment: Processed
- AI Analysis: Failed
- Manual Investigation: Required

### AI Service Error

{error}

The deterministic SOC assessment remains the
source of truth for the incident severity.
""".strip()