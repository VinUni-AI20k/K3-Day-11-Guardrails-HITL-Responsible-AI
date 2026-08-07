"""Local tests for layers not covered by tests/public.

Rate limiter, audit log, monitoring alerts and the egress policy edge cases.
All offline — no LLM call, so they can run on every edit.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC))


def test_rate_limiter_blocks_after_max_requests():
    from assignment.rate_limiter import RateLimitPlugin

    plugin = RateLimitPlugin(max_requests=10, window_seconds=60)
    ctx = SimpleNamespace(user_id="user-1")
    results = [
        asyncio.run(plugin.on_user_message_callback(invocation_context=ctx, user_message=None))
        for _ in range(15)
    ]
    assert sum(1 for r in results if r is None) == 10
    assert sum(1 for r in results if r is not None) == 5
    assert plugin.blocked_count == 5


def test_rate_limiter_is_per_user():
    from assignment.rate_limiter import RateLimitPlugin

    plugin = RateLimitPlugin(max_requests=2, window_seconds=60)
    a, b = SimpleNamespace(user_id="a"), SimpleNamespace(user_id="b")
    for ctx in (a, a, b, b):
        assert asyncio.run(
            plugin.on_user_message_callback(invocation_context=ctx, user_message=None)
        ) is None
    assert asyncio.run(
        plugin.on_user_message_callback(invocation_context=a, user_message=None)
    ) is not None


def test_audit_log_correlates_input_and_output(tmp_path):
    from assignment.audit_log import AuditLogPlugin

    audit = AuditLogPlugin()
    audit.record_input(user_id="u1", text="what is the savings rate", request_id="req-1")
    audit.record_output(user_id="u1", text="4.25%", blocked=False, layer=None, request_id="req-1")
    assert len(audit.logs) == 1
    entry = audit.logs[0]
    assert entry["request_id"] == "req-1"
    assert entry["user_id"] == "u1"
    assert entry["blocked"] is False
    assert entry["latency_ms"] >= 0

    out = tmp_path / "audit_log.json"
    audit.export_json(str(out))
    assert json.loads(out.read_text(encoding="utf-8"))[0]["request_id"] == "req-1"


def test_monitoring_alerts_on_high_block_rate(tmp_path):
    from assignment.monitoring import MonitoringAlert

    monitor = MonitoringAlert(total_requests=10, blocked_requests=8, rate_limit_hits=6,
                              judge_checks=10, judge_fails=5)
    alerts = monitor.check_metrics()
    metrics = {a.metric for a in alerts}
    assert {"block_rate", "rate_limit_hits", "judge_fail_rate"} <= metrics

    out = tmp_path / "metrics.json"
    monitor.export_json(str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["block_rate"] == 0.8
    assert len(data["alerts"]) >= 3


def test_egress_rejects_lookalike_subdomain_and_pii():
    from assignment.pipeline import is_egress_allowed

    assert is_egress_allowed(
        "https://api.vinbank.example.evil.com/v1/transfers", "transfer 500000"
    ) is False
    assert is_egress_allowed(
        "http://api.vinbank.example/v1/transfers", "transfer 500000"
    ) is False
    assert is_egress_allowed(
        "https://api.vinbank.example/v1/transfers", "contact 0901234567"
    ) is False
    assert is_egress_allowed(
        "https://api.vinbank.example/v1/transfers", "email me at a@b.com"
    ) is False
    assert is_egress_allowed(
        "https://cases.vinbank.example/v1/cases", "case opened for late transfer"
    ) is True
