"""
Lab 11 — Configuration & API Key Setup
"""
import os


def setup_api_key(*, prompt: bool = True):
    """Load Google API key from environment or optionally prompt.

    Returns True if a key is available.
    """
    if "GOOGLE_API_KEY" not in os.environ or not os.environ.get("GOOGLE_API_KEY"):
        if prompt and sys_stdin_is_tty():
            os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
        else:
            return False
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")
    return True


def sys_stdin_is_tty() -> bool:
    import sys
    return hasattr(sys.stdin, "isatty") and sys.stdin.isatty()


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
