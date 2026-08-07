"""
Lab 11 — Configuration & API Key Setup
"""
import os


def setup_api_key():
    """Select the configured provider without changing existing fallbacks."""
    requested = os.environ.get("AI_PROVIDER", "").casefold()
    if requested == "gemini" and os.environ.get("GOOGLE_API_KEY"):
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
        print("Google API key loaded.")
        return
    if requested == "openrouter" and os.environ.get("OPENROUTER_API_KEY"):
        print("OpenRouter API key loaded.")
        return
    if os.environ.get("OPENAI_API_KEY"):
        os.environ["AI_PROVIDER"] = "openai"
        print("OpenAI API key loaded.")
        return
    if os.environ.get("OPENROUTER_API_KEY"):
        os.environ["AI_PROVIDER"] = "openrouter"
        print("OpenRouter API key loaded.")
        return
    if os.environ.get("GOOGLE_API_KEY"):
        os.environ["AI_PROVIDER"] = "gemini"
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
        print("Google API key loaded.")
        return
    os.environ["OPENAI_API_KEY"] = input("Enter OpenAI API Key: ").strip()
    os.environ["AI_PROVIDER"] = "openai"
    print("OpenAI API key loaded.")


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
