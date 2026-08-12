import os

from dotenv import load_dotenv


load_dotenv()


# ============================================================
# API KEYS
# ============================================================

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


# ============================================================
# AI MODEL
# ============================================================

MODEL_NAME = "openai/gpt-oss-20b"


# ============================================================
# CONFIGURATION VALIDATION
# ============================================================

def validate_config():
    """
    Validate required environment variables.
    """

    missing = []

    if not OPENROUTER_API_KEY:
        missing.append("OPENROUTER_API_KEY")

    if not ABUSEIPDB_API_KEY:
        missing.append("ABUSEIPDB_API_KEY")

    if missing:
        raise RuntimeError(
            "Missing required environment variables: "
            + ", ".join(missing)
        )