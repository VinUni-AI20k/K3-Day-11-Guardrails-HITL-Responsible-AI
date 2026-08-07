"""
Provider-aware helper for direct LLM calls.

The ADK agents in this lab still use the Gemini-backed agent runtime, but
the direct model calls used for judging and synthetic attack generation can
switch between Gemini and OpenAI-compatible endpoints via environment vars.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model: str
    api_key: str | None = None
    base_url: str | None = None


def _normalize_provider(provider: str | None) -> str:
    value = (provider or os.getenv("MODEL_PROVIDER") or "gemini").strip().lower()
    if value not in {"gemini", "openai"}:
        return "gemini"
    return value


def resolve_model_config(provider: str | None = None) -> ModelConfig:
    """Resolve the direct-text model config from environment variables."""
    resolved = _normalize_provider(provider)
    if resolved == "openai":
        return ModelConfig(
            provider="openai",
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini",
            api_key=os.getenv("OPENAI_API_KEY") or None,
            base_url=os.getenv("OPENAI_BASE_URL") or None,
        )
    return ModelConfig(
        provider="gemini",
        model=os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite").strip()
        or "gemini-3.1-flash-lite",
        api_key=os.getenv("GOOGLE_API_KEY") or None,
        base_url=None,
    )


def resolve_agent_model(default: str = "gemini-3.1-flash-lite") -> str:
    """Resolve the ADK agent model string."""
    return os.getenv("AGENT_MODEL", default).strip() or default


def _openai_text(prompt: str, *, system: str | None, cfg: ModelConfig) -> str:
    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover - dependency issue
        raise RuntimeError(
            "openai package is not installed. Run pip install -r requirements.txt"
        ) from exc

    client = OpenAI(api_key=cfg.api_key, base_url=cfg.base_url)
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    response = client.chat.completions.create(
        model=cfg.model,
        messages=messages,
        temperature=0.0,
    )
    content = response.choices[0].message.content if response.choices else ""
    return (content or "").strip()


def _gemini_text(prompt: str, *, system: str | None, cfg: ModelConfig) -> str:
    try:
        from google import genai
    except ImportError as exc:  # pragma: no cover - dependency issue
        raise RuntimeError(
            "google-genai package is not installed. Run pip install -r requirements.txt"
        ) from exc

    client = genai.Client(api_key=cfg.api_key)
    full_prompt = f"{system}\n\n{prompt}" if system else prompt
    response = client.models.generate_content(
        model=cfg.model,
        contents=full_prompt,
    )
    text = getattr(response, "text", None) or ""
    return text.strip()


def generate_text(
    prompt: str,
    *,
    system: str | None = None,
    provider: str | None = None,
    model: str | None = None,
) -> str:
    """Generate a single text completion from the configured provider."""
    cfg = resolve_model_config(provider=provider)
    if model:
        cfg = ModelConfig(
            provider=cfg.provider,
            model=model,
            api_key=cfg.api_key,
            base_url=cfg.base_url,
        )
    if cfg.provider == "openai":
        if not cfg.api_key:
            raise RuntimeError("OPENAI_API_KEY is missing.")
        return _openai_text(prompt, system=system, cfg=cfg)
    if not cfg.api_key:
        raise RuntimeError("GOOGLE_API_KEY is missing.")
    return _gemini_text(prompt, system=system, cfg=cfg)


def extract_json_from_text(text: str):
    """Best-effort JSON extraction for model-generated payloads."""
    if not text:
        return None
    candidates = []
    start = text.find("[")
    end = text.rfind("]") + 1
    if start >= 0 and end > start:
        candidates.append(text[start:end])
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        candidates.append(text[start:end])
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None


def normalize_text(text: str) -> str:
    """Collapse code fences and trim whitespace for judge parsing."""
    text = re.sub(r"```(?:json|yaml|text)?", "", text or "", flags=re.IGNORECASE)
    text = text.replace("```", "")
    return text.strip()
