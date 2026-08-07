"""
Lab 11 — Helper Utilities
"""
import json
import re

from google.genai import types


def _balanced_slices(text: str, opener: str, closer: str) -> list[str]:
    """Yield every balanced ``opener…closer`` slice, outermost first.

    Why: model replies wrap JSON in prose or a ``` fence, and the naive
    first-opener to last-closer slice swallows a bracket from the prose and
    fails to parse. Scanning every candidate start position is what makes
    judge / red-team parsing reproducible instead of luck-of-the-sampling.
    """
    slices = []
    for start in [m.start() for m in re.finditer(re.escape(opener), text)]:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    slices.append(text[start:i + 1])
                    break
    return slices


def extract_json_array(text: str) -> list:
    """Pull the first well-formed JSON array of objects out of a model reply."""
    if not text:
        return []

    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
    candidates = [fenced.group(1)] if fenced else []
    candidates += _balanced_slices(text, "[", "]")

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            return parsed
    return []


def extract_json_object(text: str) -> dict | None:
    """Pull the first well-formed JSON object out of a model reply.

    Returns None when nothing parses — callers decide whether that is a
    fail-open or a fail-closed condition rather than guessing here.
    """
    if not text:
        return None

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = [fenced.group(1)] if fenced else []
    candidates += _balanced_slices(text, "{", "}")

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


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
