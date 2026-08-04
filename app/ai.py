from google import genai

from config import GEMINI_API_KEY, MODEL_NAME
from prompts import SYSTEM_PROMPT


client = genai.Client(api_key=GEMINI_API_KEY)


def analyze_alert(alert):

    prompt = f"""
{SYSTEM_PROMPT}

Alert:

{alert}
"""

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt
    )

    return response.text
