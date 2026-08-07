"""
Assignment 11 — Rate Limiter starter (TODO).

Sliding-window, per-user rate limiting. Blocks abuse that other
guardrail layers do not address (flooding / cost attacks).
"""
from __future__ import annotations

from collections import defaultdict, deque
import time

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        # Sliding-window rate limiter.
        #
        # Each user gets a deque of timestamps. On every request:
        # 1. Expire any timestamps older than (now - window_seconds).
        # 2. If what remains is >= max_requests, the user has sent too many
        #    requests inside the window — block and tell them how long to wait.
        # 3. Otherwise, record this request's timestamp and allow it.
        #
        # The reject-first-then-append ordering is deliberate: it means the
        # (max_requests + 1)th request inside the same window is blocked,
        # matching the test expectation "~15 same-user requests → ~10 pass,
        # the rest blocked".
        #
        # This is a *per-user* control, not a global one — one noisy user
        # never starves others. For a real deployment the deques belong in
        # Redis so rate-limit state survives process restarts and is shared
        # across workers.
        while window and window[0] < now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            wait = self.window_seconds - (now - window[0])
            self.blocked_count += 1
            return self._block_response(
                f"Rate limit exceeded. Try again in {wait:.0f}s."
            )

        window.append(now)
        return None
