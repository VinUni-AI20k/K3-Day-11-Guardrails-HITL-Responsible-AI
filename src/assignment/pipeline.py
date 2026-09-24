"""
Checkpoint 3 — Defense-in-depth pipeline assembly.

Wire rate limiter + lab guardrails + audit + monitoring + egress.
You may use Google ADK plugins, LangGraph, NeMo, or pure Python.
"""
from __future__ import annotations

from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert


def is_egress_allowed(destination: str, payload: str) -> bool:
    """Enforce a destination allowlist before any data leaves the agent.

    Return ``True`` only for an approved VinBank HTTPS endpoint and ordinary
    banking payload. Return ``False`` for unknown domains and payloads that
    contain a password, API key, database host, phone number or email address.
    Do not let the LLM's prose decide this policy.
    """
    raise NotImplementedError("Implement is_egress_allowed")


def build_production_plugins(
    *,
    max_requests: int = 10,
    window_seconds: int = 60,
    use_llm_judge: bool = False,
) -> list:
    """Return an ordered list of plugins / layers:

    1. RateLimitPlugin
    2. InputGuardrailPlugin  (from guardrails.input_guardrails)
    3. OutputGuardrailPlugin  (from guardrails.output_guardrails)
       (LLM-as-Judge / NeMo are optional)

    Audit/monitoring can be plugins or side observers — document your choice.
    The action gateway calls ``is_egress_allowed`` separately before any sink.
    """
    raise NotImplementedError("Implement build_production_plugins")


def build_observability():
    """Return (AuditLogPlugin(), MonitoringAlert())."""
    raise NotImplementedError("Implement build_observability")


async def run_assignment_suite(pipeline, student_id: str) -> dict:
    """Run Tests 1–4 from CHECKPOINTS.md (Checkpoint 3) and
    return a dict matching schemas/results.schema.json.

    Write:
      outputs/results.json
      outputs/audit_log.json
      outputs/metrics.json
    """
    raise NotImplementedError("Implement run_assignment_suite")
