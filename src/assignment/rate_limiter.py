"""
Assignment 11 — Rate Limiter starter (TODO).

Sliding-window, per-user rate limiting. Blocks abuse that other
guardrail layers do not address (flooding / cost attacks).
"""
from __future__ import annotations

from collections import defaultdict, deque
import time
from threading import RLock

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60, clock=None):
        super().__init__(name="rate_limiter")
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("max_requests and window_seconds must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0
        self._clock = clock or time.time
        self._lock = RLock()

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        self.total_count += 1
        raw_user_id = getattr(invocation_context, "user_id", None)
        user_id = str(raw_user_id).strip() if raw_user_id is not None else ""
        user_id = user_id or "anonymous"
        now = float(self._clock())
        window = self.user_windows[user_id]

        with self._lock:
            cutoff = now - self.window_seconds
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= self.max_requests:
                wait = max(0.0, self.window_seconds - (now - window[0]))
                self.blocked_count += 1
                return self._block_response(
                    f"Rate limit exceeded. Try again in {max(1, int(wait + 0.999))}s."
                )
            window.append(now)
        return None
