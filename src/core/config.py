"""
Lab 11 — Configuration & API Key Setup
"""
import os
from pathlib import Path

# Repo root: src/core/config.py -> src -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[2]


def setup_api_key():
    """Load Google API key from .env, then environment, then prompt.

    Why .env comes first: README §1 tells students to put the key in .env, but
    nothing here ever read it — so every `python main.py` blocked on an input()
    prompt, and died with EOFError in any non-interactive run (CI, piped shell,
    scheduled grading).
    """
    if "GOOGLE_API_KEY" not in os.environ:
        try:
            from dotenv import load_dotenv

            load_dotenv(_REPO_ROOT / ".env")
        except ImportError:
            pass

    if not os.environ.get("GOOGLE_API_KEY", "").strip():
        os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")


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
