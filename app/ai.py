from openai import OpenAI

from config import OPENROUTER_API_KEY, MODEL_NAME
from prompts import SYSTEM_PROMPT


client = OpenAI(
    api_key=OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1",
)


def analyze_alert(alert_text):

    prompt = f"""
{SYSTEM_PROMPT}

================ INCIDENT DATA ================

{alert_text}

================================================

Analyze the incident according to the SOC analysis rules.
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

        return response.choices[0].message.content


    except Exception as error:

        print("\n========== AI ERROR ==========\n")
        print("The AI analysis request failed.")
        print(f"Error: {error}")

        return """
## AI Analysis Unavailable

The SOC alert and threat intelligence were successfully collected,
but the AI analysis service did not return a valid response.

### Status

- Wazuh Alert: Successfully processed
- Threat Intelligence: Successfully processed
- AI Analysis: Failed
- Incident Classification: Requires manual investigation

Please retry the analysis.
"""