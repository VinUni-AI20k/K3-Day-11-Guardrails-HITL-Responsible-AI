"""Configuration for the DeepSeek-backed VinBank lab."""
from __future__ import annotations

import os
import re
from pathlib import Path

from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / ".env", override=False)
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
# ``deepseek-chat`` was retired in July 2026.  V4 Flash is the current,
# economical default; callers can select V4 Pro through the environment.
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")


def load_environment() -> None:
    """Load the repository ``.env`` without overwriting shell variables."""
    load_dotenv(REPO_ROOT / ".env", override=False)


def get_deepseek_api_key() -> str | None:
    """Return the DeepSeek key, accepting the starter's legacy variable name.

    The repository originally labelled the field ``GOOGLE_API_KEY``.  Existing
    local ``.env`` files continue to work, but new setups should use
    ``DEEPSEEK_API_KEY``.  The value is never logged.
    """
    load_environment()
    value = (
        os.environ.get("DEEPSEEK_API_KEY", "").strip()
        or os.environ.get("GOOGLE_API_KEY", "").strip()
    )
    if not value or value.startswith("your-"):
        return None
    return value


def setup_api_key():
    """Load DeepSeek credentials without blocking automated/offline runs."""
    key = get_deepseek_api_key()
    if key:
        # Normalize the legacy starter variable in process memory only.
        os.environ.setdefault("DEEPSEEK_API_KEY", key)
        print(f"DeepSeek configured (model={DEEPSEEK_MODEL}).")
        return True
    print("DeepSeek key not found; deterministic offline paths remain available.")
    return False


def get_student_id() -> str:
    """Read STUDENT_ID or infer the course-format ID from the repo name."""
    configured = os.environ.get("STUDENT_ID", "").strip()
    if configured:
        return configured
    match = re.search(r"\b(\d[A-Z]\d{9})\b", REPO_ROOT.name, re.IGNORECASE)
    return match.group(1).upper() if match else "SE00000"


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
