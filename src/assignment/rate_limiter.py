"""Per-user sliding-window rate limiting for the VinBank pipeline.

The limiter deliberately runs before any model call.  Apart from reducing
abuse, this also bounds the cost of a prompt-flooding attack.  The small
Google-ADK compatibility shim keeps the deterministic policy testable in an
offline environment; when ADK is installed the real ADK types are used.
"""
from __future__ import annotations

from collections import defaultdict, deque
from threading import RLock
import time
from typing import Callable

try:  # ADK is optional for the pure-Python/offline assignment suite.
    from google.adk.plugins import base_plugin
    from google.genai import types
except ImportError:  # pragma: no cover - exercised only without optional ADK.
    class _Part:
        def __init__(self, text: str = ""):
            self.text = text

        @classmethod
        def from_text(cls, *, text: str):
            return cls(text=text)

    class _Content:
        def __init__(self, *, role: str, parts: list):
            self.role = role
            self.parts = parts

    class _Types:
        Content = _Content
        Part = _Part

    class _BasePlugin:
        def __init__(self, name: str):
            self.name = name

    class _BasePluginModule:
        BasePlugin = _BasePlugin

    types = _Types()
    base_plugin = _BasePluginModule()


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: int = 60,
        *,
        clock: Callable[[], float] | None = None,
    ):
        if isinstance(max_requests, bool) or not isinstance(max_requests, int):
            raise TypeError("max_requests must be an integer")
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)):
            raise TypeError("window_seconds must be a number")
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0")

        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque[float]] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0
        self._lock = RLock()
        # Keep ``None`` rather than capturing ``time.time`` so test/incident
        # replay can monkeypatch the module clock after construction.
        self._clock = clock

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    def check_request(self, user_id: str | None, *, now: float | None = None) -> tuple[bool, float]:
        """Apply the sliding-window policy.

        Returns ``(allowed, retry_after_seconds)``.  Supplying ``now`` makes
        boundary cases deterministic in tests and incident replay.  Rejected
        requests are not appended to the window, so an attacker cannot extend
        their own lockout indefinitely by continuing to send requests.
        """
        with self._lock:
            self.total_count += 1
            principal = str(user_id or "anonymous")
            timestamp = float(
                (self._clock() if self._clock is not None else time.time())
                if now is None
                else now
            )
            window = self.user_windows[principal]
            cutoff = timestamp - float(self.window_seconds)

            # A request exactly one window old is no longer in the active window.
            while window and window[0] <= cutoff:
                window.popleft()

            if len(window) >= self.max_requests:
                self.blocked_count += 1
                retry_after = max(
                    0.0,
                    float(self.window_seconds) - (timestamp - window[0]),
                )
                return False, retry_after

            window.append(timestamp)
            return True, 0.0

    def reset(self, user_id: str | None = None) -> None:
        """Reset one principal, or all limiter state when ``user_id`` is None."""
        with self._lock:
            if user_id is None:
                self.user_windows.clear()
                self.blocked_count = 0
                self.total_count = 0
                return
            self.user_windows.pop(str(user_id or "anonymous"), None)

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        user_id = getattr(invocation_context, "user_id", None)
        if not user_id:
            session = getattr(invocation_context, "session", None)
            user_id = getattr(session, "user_id", None)

        allowed, retry_after = self.check_request(user_id)
        if allowed:
            return None
        return self._block_response(
            f"Rate limit exceeded. Try again in {retry_after:.0f}s."
        )
