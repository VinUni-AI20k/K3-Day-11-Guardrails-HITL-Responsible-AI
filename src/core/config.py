"""
Lab 11 — Configuration & API Key Setup
"""
import os

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None


def setup_api_key(parts=None):
    """Load Google/OpenAI API keys from environment or prompt.

    In offline lab mode we avoid interactive prompts and inject a harmless
    placeholder so deterministic fallbacks can run without blocking stdin.
    """
    if load_dotenv is not None:
        load_dotenv()

    provider = (os.environ.get("MODEL_PROVIDER") or "gemini").strip().lower()
    remote_enabled = (os.environ.get("ALLOW_REMOTE_AGENT") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    # Part 5 can run with OpenAI-only direct calls, so avoid requiring a
    # Google key when that is the only requested part.
    if provider == "openai" and parts == [5]:
        if "OPENAI_API_KEY" not in os.environ or not os.environ["OPENAI_API_KEY"].strip():
            if remote_enabled:
                os.environ["OPENAI_API_KEY"] = input("Enter OpenAI API Key: ").strip()
            else:
                os.environ["OPENAI_API_KEY"] = "offline-dummy-key"
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
        print("API key loaded.")
        return

    if "GOOGLE_API_KEY" not in os.environ or not os.environ["GOOGLE_API_KEY"].strip():
        if remote_enabled:
            os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ").strip()
        else:
            os.environ["GOOGLE_API_KEY"] = "offline-dummy-key"
            print("No GOOGLE_API_KEY set; using offline fallback mode.")

    if os.environ.get("GOOGLE_API_KEY", "").strip() and not os.environ.get("ALLOW_REMOTE_AGENT"):
        os.environ["ALLOW_REMOTE_AGENT"] = "1"

    if provider == "openai":
        if "OPENAI_API_KEY" not in os.environ or not os.environ["OPENAI_API_KEY"].strip():
            if remote_enabled:
                os.environ["OPENAI_API_KEY"] = input("Enter OpenAI API Key: ").strip()
            else:
                os.environ["OPENAI_API_KEY"] = "offline-dummy-key"

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
