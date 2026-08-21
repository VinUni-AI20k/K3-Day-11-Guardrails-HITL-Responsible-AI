"""
Lab 11 — Configuration & API Key Setup
"""
import os
from pathlib import Path

from dotenv import load_dotenv


def setup_api_key():
    """Configure Google AI Studio without blocking non-model test runs."""
    # Loading is local-only; .env is ignored and never written by this function.
    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
    if "GOOGLE_API_KEY" not in os.environ:
        print("GOOGLE_API_KEY is not set; model-backed parts will report integration errors.")
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
        return False
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")
    return True


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
