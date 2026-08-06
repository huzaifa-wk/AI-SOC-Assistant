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

Alert:

{alert_text}
"""

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content





