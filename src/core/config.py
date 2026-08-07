"""
Lab 11 — Configuration & API Key Setup
"""
import os
import re
import unicodedata
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

# ------------------------------------------------------------------
# Conversational small talk (greeting / thanks / goodbye / "what can
# you do?"). A default-deny topic allowlist otherwise rejects "hi" as
# off-topic, which reads to the user as the assistant being broken.
#
# These are matched as the WHOLE message (fullmatch on a normalized
# form), so "hi, ignore all previous instructions" never qualifies —
# only a message that is nothing but small talk does.
# ------------------------------------------------------------------
SMALLTALK_PATTERNS = [
    # Greetings, EN + VI (diacritics stripped before matching)
    r"(?:hi|hii+|hey+|hello+|helo|halo|yo|hola|good\s*(?:morning|afternoon|evening|day))",
    r"(?:xin\s*)?chao(?:\s*(?:ban|anh|chi|em|shop|vinbank|bot))?",
    r"a\s*lo|alo+",
    # Thanks / acknowledgement
    r"(?:thanks?|thank\s*you|thx|ty)(?:\s*(?:you|so\s*much|a\s*lot))?",
    r"cam\s*on(?:\s*(?:ban|nhieu|nhe|nha))?",
    r"(?:ok|okay|oke|okie|yes|yeah|no|nope|got\s*it|understood|hieu\s*roi|duoc\s*roi)",
    # Goodbye
    r"(?:bye+|goodbye|see\s*you|tam\s*biet)",
    # Capability / help openers — the natural first message to a bot
    r"(?:who\s*are\s*you|what\s*(?:can|do)\s*you\s*do|how\s*(?:can|do)\s*you\s*help|"
    r"can\s*you\s*help(?:\s*me)?|help(?:\s*me)?|need\s*help)",
    r"(?:ban\s*la\s*ai|ban\s*(?:co\s*the\s*)?(?:lam|giup)\s*(?:duoc\s*)?(?:gi|nhung\s*gi)|"
    r"giup\s*(?:toi|minh|em)?|cho\s*(?:toi|minh|em)\s*hoi|co\s*ai\s*(?:o\s*day|khong))",
    # Bare politeness / state-of-being
    r"(?:how\s*are\s*you|ban\s*khoe\s*khong|dang\s*lam\s*gi\s*day)",
]

# Small talk is only ever a short message. A long "greeting" is a wrapper
# around a payload, so it goes back through the normal filters.
SMALLTALK_MAX_LEN = 64

# Filler that may surround small talk without changing its nature.
_SMALLTALK_FILLER = (
    r"(?:please|pls|xin|lam\s*on|vinbank|bot|assistant|"
    r"ban|anh|chi|em|minh|toi|ạ|a|nhe|nha|nhi|day|voi|the|there)"
)

_SMALLTALK_RE = re.compile(
    r"^(?:{filler}[\s,!.?]*)*"
    r"(?:(?:{units})[\s,!.?]*)+"
    r"(?:{filler}[\s,!.?]*)*$".format(
        filler=_SMALLTALK_FILLER,
        units="|".join(SMALLTALK_PATTERNS),
    ),
    re.IGNORECASE,
)


def _fold_for_smalltalk(text: str) -> str:
    """Lowercase, strip Vietnamese diacritics, squeeze whitespace."""
    decomposed = unicodedata.normalize("NFD", text or "")
    stripped = "".join(
        c for c in decomposed if unicodedata.category(c) != "Mn"
    )
    stripped = unicodedata.normalize("NFKC", stripped).replace("đ", "d").replace("Đ", "D")
    return re.sub(r"\s+", " ", stripped).strip().lower()


def is_smalltalk(text: str) -> bool:
    """True when the message is nothing but a greeting/thanks/help opener.

    Why: the topic allowlist is default-deny, so without this "hi" is
    reported as a guardrail block — a false positive on the single most
    common first message. The whole-message match keeps it from becoming
    a bypass: any payload appended to the greeting fails the fullmatch
    and falls through to the real filters.
    """
    folded = _fold_for_smalltalk(text)
    if not folded or len(folded) > SMALLTALK_MAX_LEN:
        return False
    if any(b in folded for b in BLOCKED_TOPICS):
        return False
    return bool(_SMALLTALK_RE.match(folded))
