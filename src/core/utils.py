"""Shared Google ADK helpers with bounded retry and safe error reporting."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
import random
import re
from typing import Awaitable, Callable
from weakref import WeakKeyDictionary

from google.genai import types


STATUS_ERROR = "error"
_LOOP_SEMAPHORES: WeakKeyDictionary = WeakKeyDictionary()


@dataclass(frozen=True)
class ModelErrorInfo:
    """Sanitized classification for an external model execution failure."""

    error_type: str
    message: str
    retryable: bool
    retry_after: float | None = None


class ModelExecutionError(RuntimeError):
    """Raise a safe, structured error after transient retries are exhausted."""

    def __init__(self, info: ModelErrorInfo):
        super().__init__(info.message)
        self.info = info


def _exception_chain(exc: BaseException):
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        nested = getattr(current, "error", None)
        current = nested if isinstance(nested, BaseException) else (current.__cause__ or current.__context__)


def classify_model_error(exc: BaseException) -> ModelErrorInfo:
    """Classify quota, timeout, and network failures without exposing credentials."""
    chain = list(_exception_chain(exc))
    names = " ".join(type(item).__name__ for item in chain).casefold()
    text = " ".join(str(item) for item in chain)
    lower = text.casefold()
    status_codes = {
        getattr(item, "status_code", None) or getattr(item, "code", None)
        for item in chain
    }
    retry_match = re.search(
        r"(?:retryDelay|retry[_ ]?after)[^0-9]{0,20}([0-9]+(?:\.[0-9]+)?)\s*s?",
        text,
        re.IGNORECASE,
    )
    retry_after = float(retry_match.group(1)) if retry_match else None
    if 429 in status_codes or "resourceexhausted" in names or "resource_exhausted" in lower or "429" in lower:
        return ModelErrorInfo("resource_exhausted", "Model quota exhausted", True, retry_after)
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)) or "timeout" in names or "timed out" in lower:
        return ModelErrorInfo("timeout", "Model request timed out", True, retry_after)
    network_tokens = ("connectionerror", "networkerror", "connecterror", "dns", "connection reset")
    if any(token in names or token in lower for token in network_tokens):
        return ModelErrorInfo("network_error", "Model network request failed", True, retry_after)
    if "api key" in lower or "credential" in lower or "unauthenticated" in lower:
        return ModelErrorInfo("authentication_error", "Model authentication is unavailable", False)
    return ModelErrorInfo("model_error", "Model execution failed", False)


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return min(maximum, max(minimum, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def _float_env(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        return min(maximum, max(minimum, float(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


async def _run_agent_once(agent, runner, user_message: str, session_id=None):
    """Perform one ADK request; retry policy is deliberately kept outside."""
    user_id = "student"
    app_name = runner.app_name

    session = None
    if session_id is not None:
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    if session is None:
        try:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )
        except Exception:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    final_response = ""
    async for event in runner.run_async(
        user_id=user_id, session_id=session.id, new_message=content
    ):
        if hasattr(event, "content") and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    final_response += part.text

    return final_response, session


async def chat_with_agent(
    agent,
    runner,
    user_message: str,
    session_id=None,
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    jitter: Callable[[float, float], float] = random.uniform,
):
    """Call an agent with bounded exponential backoff for transient failures.

    Mock runners skip real waiting, while production calls honor the environment
    controls documented in ``.env.example``.
    """
    is_mock = type(runner).__module__.startswith("unittest.mock")
    return await retry_model_call(
        lambda: _run_agent_once(agent, runner, user_message, session_id),
        is_mock=is_mock,
        sleep=sleep,
        jitter=jitter,
    )


async def retry_model_call(
    operation: Callable[[], Awaitable],
    *,
    is_mock: bool = False,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    jitter: Callable[[float, float], float] = random.uniform,
):
    """Run any async model operation with shared concurrency and retry policy."""
    retries = _int_env("MODEL_MAX_RETRIES", 3, 0, 8)
    base_delay = _float_env("MODEL_REQUEST_DELAY_SECONDS", 5.0, 0.0, 120.0)
    concurrency = _int_env("MODEL_MAX_CONCURRENCY", 1, 1, 16)
    loop = asyncio.get_running_loop()
    cached = _LOOP_SEMAPHORES.get(loop)
    if cached is None or cached[0] != concurrency:
        cached = (concurrency, asyncio.Semaphore(concurrency))
        _LOOP_SEMAPHORES[loop] = cached
    async with cached[1]:
        for attempt in range(retries + 1):
            try:
                return await operation()
            except Exception as exc:
                info = classify_model_error(exc)
                if not info.retryable or attempt >= retries:
                    raise ModelExecutionError(info) from exc
                schedule = (base_delay, base_delay * 3, info.retry_after or base_delay * 6)
                delay = schedule[min(attempt, len(schedule) - 1)]
                if not is_mock and delay > 0:
                    await sleep(delay + jitter(0.0, min(1.0, delay * 0.1)))
