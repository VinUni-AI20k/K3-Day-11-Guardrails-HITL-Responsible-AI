"""DeepSeek client and framework-neutral runner utilities."""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from core.compat import LlmResponse, content_text, types
from core.config import (
    DEEPSEEK_BASE_URL,
    DEEPSEEK_MODEL,
    get_deepseek_api_key,
)


@dataclass
class DeepSeekAgent:
    """Simple agent definition independent of an orchestration framework."""

    name: str
    instruction: str
    model: str = DEEPSEEK_MODEL


@dataclass
class SimpleSession:
    id: str


class DeepSeekRunner:
    """Apply plugins around an OpenAI-compatible DeepSeek chat completion."""

    def __init__(
        self,
        agent: DeepSeekAgent,
        app_name: str,
        plugins=None,
        *,
        require_live: bool = False,
    ) -> None:
        self.agent = agent
        self.app_name = app_name
        self.plugins = list(plugins or [])
        self.require_live = require_live
        self._history: dict[str, list[dict[str, str]]] = {}

    async def chat(self, user_message: str, *, session_id: str | None = None) -> str:
        content = types.Content(
            role="user", parts=[types.Part.from_text(text=user_message)]
        )
        for plugin in self.plugins:
            callback = getattr(plugin, "on_user_message_callback", None)
            if callback:
                replacement = await callback(
                    invocation_context=None, user_message=content
                )
                if replacement is not None:
                    return content_text(replacement)

        session_key = session_id or uuid.uuid4().hex
        history = self._history.setdefault(session_key, [])
        response_text = await deepseek_chat(
            self.agent.instruction,
            user_message,
            model=self.agent.model,
            history=history,
            fallback=(
                None
                if self.require_live
                else _offline_banking_response(user_message, self.agent.name)
            ),
        )
        history.extend(
            [
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": response_text},
            ]
        )

        response = LlmResponse(
            content=types.Content(
                role="model", parts=[types.Part.from_text(text=response_text)]
            )
        )
        for plugin in self.plugins:
            callback = getattr(plugin, "after_model_callback", None)
            if callback:
                updated = await callback(callback_context=None, llm_response=response)
                if updated is not None:
                    response = updated
        return content_text(response.content)


def _client() -> OpenAI:
    key = get_deepseek_api_key()
    if not key:
        raise RuntimeError("DEEPSEEK_API_KEY is not configured")
    return OpenAI(api_key=key, base_url=DEEPSEEK_BASE_URL, timeout=45.0)


def _sync_completion(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str,
    response_format: dict | None = None,
    max_tokens: int = 700,
    history: list[dict[str, str]] | None = None,
) -> str:
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": (
            [{"role": "system", "content": system_prompt}]
            + list(history or [])
            + [{"role": "user", "content": user_prompt}]
        ),
        "max_tokens": max_tokens,
        "temperature": 0.2,
        # Non-thinking mode reduces cost/latency for the lab's classification
        # and short customer-service calls.
        "extra_body": {"thinking": {"type": "disabled"}},
    }
    if response_format:
        kwargs["response_format"] = response_format
    response = _client().chat.completions.create(**kwargs)
    return (response.choices[0].message.content or "").strip()


async def deepseek_chat(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str = DEEPSEEK_MODEL,
    response_format: dict | None = None,
    max_tokens: int = 700,
    fallback: str | None = None,
    history: list[dict[str, str]] | None = None,
) -> str:
    """Call DeepSeek without blocking the event loop.

    A caller-provided fallback is used only for repeatable local grading when
    credentials/network are unavailable. Security policies never delegate their
    allow/block decisions to this model call.
    """
    try:
        return await asyncio.to_thread(
            _sync_completion,
            system_prompt,
            user_prompt,
            model=model,
            response_format=response_format,
            max_tokens=max_tokens,
            history=history,
        )
    except Exception:
        if fallback is not None:
            return fallback
        raise


async def deepseek_json(
    system_prompt: str,
    user_prompt: str,
    *,
    fallback: dict | None = None,
    max_tokens: int = 1400,
) -> dict:
    """Request and parse one JSON object from DeepSeek."""
    try:
        text = await deepseek_chat(
            system_prompt,
            user_prompt,
            response_format={"type": "json_object"},
            max_tokens=max_tokens,
        )
        return json.loads(text)
    except (json.JSONDecodeError, RuntimeError, Exception):
        if fallback is not None:
            return fallback
        raise


def _offline_banking_response(message: str, agent_name: str) -> str:
    """Conservative local response; it never invents account-specific facts."""
    text = (message or "").casefold()
    if not text.strip():
        return "Please enter a VinBank banking question."
    if "unsafe" in agent_name:
        # Never fabricate a successful red-team transcript. A leak counts only
        # when the live DeepSeek target actually returns the canary.
        return "Offline fallback: live DeepSeek response unavailable; no leak claimed."
    if any(term in text for term in ("interest", "lãi suất", "savings", "tiết kiệm")):
        return (
            "VinBank savings rates depend on term and product. Please check the "
            "official rate table or ask a branch for the current verified rate."
        )
    if any(term in text for term in ("transfer", "chuyển tiền")):
        return (
            "I can explain a transfer, but sending money requires confirmation "
            "and human approval for high-risk actions."
        )
    return "I can help with VinBank accounts, cards, loans, savings and transfers."


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to the agent and get the response.

    Args:
        agent: The LlmAgent instance
        runner: The InMemoryRunner instance
        user_message: Plain text message to send
        session_id: Optional session ID to continue a conversation

    Returns:
        Tuple of (response_text, session)
    """
    if hasattr(runner, "chat"):
        session = SimpleSession(session_id or uuid.uuid4().hex)
        response = await runner.chat(user_message, session_id=session.id)
        return response, session

    # Optional ADK compatibility for users who install that framework.
    user_id = "student"
    app_name = runner.app_name
    session = await runner.session_service.create_session(
        app_name=app_name, user_id=user_id
    )
    content = types.Content(
        role="user", parts=[types.Part.from_text(text=user_message)]
    )
    final_response = ""
    async for event in runner.run_async(
        user_id=user_id, session_id=session.id, new_message=content
    ):
        final_response += content_text(getattr(event, "content", None))
    return final_response, session
