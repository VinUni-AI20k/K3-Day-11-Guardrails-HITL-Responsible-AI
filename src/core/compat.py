"""Small compatibility layer for guardrail callback contracts.

The assignment originally used Google ADK types.  The submitted solution uses
DeepSeek directly, but keeping the same callback shape makes the guardrail
plugins easy to test and portable to ADK when that optional package is present.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

try:  # pragma: no cover - exercised only when the optional ADK is installed
    from google.adk.agents.invocation_context import InvocationContext
    from google.adk.plugins import base_plugin
    from google.genai import types
except ImportError:
    class BasePlugin:
        """Framework-neutral subset of ADK's ``BasePlugin``."""

        def __init__(self, name: str = "plugin") -> None:
            self.name = name

    class Part:
        def __init__(self, text: str | None = None) -> None:
            self.text = text

        @classmethod
        def from_text(cls, *, text: str) -> "Part":
            return cls(text=text)

    @dataclass
    class Content:
        role: str
        parts: list[Part] = field(default_factory=list)

    class InvocationContext:  # noqa: D101 - marker type for callbacks
        pass

    base_plugin = SimpleNamespace(BasePlugin=BasePlugin)
    types = SimpleNamespace(Content=Content, Part=Part)


@dataclass
class LlmResponse:
    """Minimal mutable model response understood by output plugins."""

    content: Any


def content_text(content: Any) -> str:
    """Extract text from either an ADK Content object or the fallback type."""
    if not content or not getattr(content, "parts", None):
        return ""
    return "".join(
        str(part.text) for part in content.parts if getattr(part, "text", None)
    )
