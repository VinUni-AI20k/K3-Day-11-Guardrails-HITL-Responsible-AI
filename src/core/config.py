"""
Lab 11 — Configuration & API Key Setup
"""
import os
from pathlib import Path


def _load_dotenv() -> None:
    """Load the repo-root .env into os.environ (if present).

    python-dotenv is already a declared dependency, but nothing in the lab
    called it — so a key sitting in .env was never visible to the process and
    setup_api_key() fell through to the interactive prompt. Loading here keeps
    the key out of the shell history and out of any committed file.

    override=False: a variable exported in the real environment always wins
    over .env, which is what you want in CI.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)


def setup_api_key():
    """Load the active provider's API key from .env, environment, or prompt."""
    _load_dotenv()
    if LLM_PROVIDER == "openai":
        if not os.environ.get("OPENAI_API_KEY", "").strip():
            os.environ["OPENAI_API_KEY"] = input("Enter OpenAI API Key: ")
    else:
        if not os.environ.get("GOOGLE_API_KEY", "").strip():
            os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print(f"API key loaded (provider={LLM_PROVIDER}, model={MODEL_NAME}).")


# ============================================================
# Model selection
#
# Every agent in the lab reads its model from get_model() rather than
# hard-coding a string, so switching provider is a one-line change here (or an
# env var) instead of an edit in six files.
#
# LLM_PROVIDER=openai  -> gpt-4o-mini via LiteLLM (needs OPENAI_API_KEY)
# LLM_PROVIDER=google  -> Gemini natively      (needs GOOGLE_API_KEY)
#
# ADK talks to non-Gemini providers through the LiteLlm wrapper, which expects
# a "<provider>/<model>" string. Gemini is native, so it takes a bare string.
# ============================================================

_load_dotenv()  # so the env vars below are readable at import time

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openai").strip().lower()

_DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "google": "gemini-2.0-flash",
}
MODEL_NAME = os.environ.get(
    "LLM_MODEL", _DEFAULT_MODELS.get(LLM_PROVIDER, "gpt-4o-mini")
).strip()


def get_model():
    """Return the model object/string to hand to LlmAgent(model=...).

    Returns a LiteLlm instance for OpenAI (ADK's adapter for non-Gemini
    providers) or a plain model-name string for Gemini, which ADK resolves
    natively. Call this per-agent rather than sharing one instance — LiteLlm
    objects carry per-agent request state.
    """
    if LLM_PROVIDER == "openai":
        from google.adk.models.lite_llm import LiteLlm

        return LiteLlm(model=f"openai/{MODEL_NAME}")
    return MODEL_NAME


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
