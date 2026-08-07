import os
from dotenv import load_dotenv

load_dotenv()

# OpenRouter
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

# AbuseIPDB
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# AI Model
MODEL_NAME = "openai/gpt-oss-20b"