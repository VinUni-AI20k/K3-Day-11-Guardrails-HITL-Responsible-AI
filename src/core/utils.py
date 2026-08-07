"""
Lab 11 — Helper Utilities
"""
import os
from types import SimpleNamespace

from google.genai import types


_provider_clients = {}
_openai_sessions: dict[tuple[str, str, str, str], list[dict[str, str]]] = {}


def _active_provider() -> str:
    return os.environ.get("AI_PROVIDER", "openai").casefold()


def _openai_enabled() -> bool:
    """Use an OpenAI-compatible provider only when its key is configured."""
    provider = _active_provider()
    if provider == "openrouter":
        return bool(os.environ.get("OPENROUTER_API_KEY"))
    return provider == "openai" and bool(os.environ.get("OPENAI_API_KEY"))


async def _chat_with_openai(agent, runner, user_message: str, session):
    """Run one concise OpenAI-compatible completion while preserving plugins."""
    from google.adk.models.llm_response import LlmResponse

    provider = _active_provider()
    if provider == "openrouter":
        api_key = os.environ["OPENROUTER_API_KEY"]
        model = os.environ.get("OPENROUTER_MODEL", "openrouter/free")
        base_url = "https://openrouter.ai/api/v1"
    else:
        api_key = os.environ["OPENAI_API_KEY"]
        model = os.environ.get("OPENAI_MODEL", "gpt-5-mini")
        base_url = None

    if provider not in _provider_clients:
        from openai import AsyncOpenAI
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        _provider_clients[provider] = AsyncOpenAI(**kwargs)
    client = _provider_clients[provider]

    user_id = "student"
    app_name = runner.app_name
    content = types.Content(role="user", parts=[types.Part.from_text(text=user_message)])
    callback_context = SimpleNamespace()
    invocation_context = SimpleNamespace(user_id=user_id)
    plugin_manager = getattr(runner, "plugin_manager", None)

    if plugin_manager is not None:
        blocked = await plugin_manager.run_on_user_message_callback(
            user_message=content, invocation_context=invocation_context
        )
        if blocked is not None:
            return "".join(
                part.text for part in blocked.parts if getattr(part, "text", None)
            ), session

    history_key = (provider, app_name, user_id, session.id)
    history = _openai_sessions.setdefault(history_key, [])
    # Preserve short conversational continuity without resending an unbounded
    # transcript on every request.
    if len(history) > 6:
        history[:] = history[-6:]
    messages = [{"role": "system", "content": str(getattr(agent, "instruction", ""))}]
    messages.extend(history)
    messages.append({"role": "user", "content": user_message})

    response = await client.chat.completions.create(
        model=model,
        messages=messages,
        max_completion_tokens=400,
    )
    text = (response.choices[0].message.content or "").strip()
    history.extend([{"role": "user", "content": user_message}, {"role": "assistant", "content": text}])

    llm_response = LlmResponse(
        content=types.Content(role="model", parts=[types.Part.from_text(text=text)])
    )
    if plugin_manager is not None:
        processed = await plugin_manager.run_after_model_callback(
            callback_context=callback_context, llm_response=llm_response
        )
        if processed is not None:
            llm_response = processed
    final = ""
    if llm_response.content and llm_response.content.parts:
        final = "".join(
            part.text for part in llm_response.content.parts if getattr(part, "text", None)
        )
    return final, session


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

    if _openai_enabled():
        return await _chat_with_openai(agent, runner, user_message, session)

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
