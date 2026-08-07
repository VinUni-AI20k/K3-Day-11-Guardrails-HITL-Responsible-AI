"""Aggregate security telemetry and threshold-based alerts."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    # Extra source-to-sink counters used in the production-readiness report.
    input_blocks: int = 0
    output_blocks: int = 0
    output_redactions: int = 0
    egress_denials: int = 0
    hitl_approved: int = 0
    hitl_rejected: int = 0
    hitl_timeouts: int = 0
    total_latency_ms: float = 0.0

    def __post_init__(self) -> None:
        if not 0 <= self.block_rate_threshold <= 1:
            raise ValueError("block_rate_threshold must be between 0 and 1")
        if self.rate_limit_hit_threshold < 1:
            raise ValueError("rate_limit_hit_threshold must be at least 1")
        if not 0 <= self.judge_fail_rate_threshold <= 1:
            raise ValueError("judge_fail_rate_threshold must be between 0 and 1")

    def observe(
        self,
        *,
        blocked: bool = False,
        layer: str | None = None,
        judge_checked: bool = False,
        judge_failed: bool = False,
        redacted: bool = False,
        egress_denied: bool = False,
        hitl_outcome: str | None = None,
        latency_ms: float = 0.0,
    ) -> None:
        """Record one request without coupling monitoring to an LLM framework."""
        self.total_requests += 1
        self.total_latency_ms += max(0.0, float(latency_ms))
        if blocked:
            self.blocked_requests += 1
        if layer == "rate_limiter":
            self.rate_limit_hits += 1
        elif layer == "input_guardrail":
            self.input_blocks += 1
        elif layer in {"output_guardrail", "llm_judge"}:
            self.output_blocks += 1
        if judge_checked:
            self.judge_checks += 1
        if judge_failed:
            self.judge_fails += 1
        if redacted:
            self.output_redactions += 1
        if egress_denied:
            self.egress_denials += 1
        if hitl_outcome == "approved":
            self.hitl_approved += 1
        elif hitl_outcome == "rejected":
            self.hitl_rejected += 1
        elif hitl_outcome in {"timeout", "timed_out"}:
            self.hitl_timeouts += 1

    def observe_hitl(self, outcome: str) -> None:
        """Record a review lifecycle event without counting a new API request."""
        if outcome == "approved":
            self.hitl_approved += 1
        elif outcome == "rejected":
            self.hitl_rejected += 1
        elif outcome in {"timeout", "timed_out"}:
            self.hitl_timeouts += 1

    def check_metrics(self) -> list[Alert]:
        """Compute current alerts idempotently.

        Replacing the list on each check avoids duplicate alerts when a metrics
        endpoint is polled repeatedly.  A threshold is considered active when
        it is met (``>=``), which is easier to reason about operationally.
        """
        block_rate = (
            self.blocked_requests / self.total_requests if self.total_requests else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        current: list[Alert] = []

        if self.total_requests and block_rate >= self.block_rate_threshold:
            current.append(
                Alert(
                    metric="block_rate",
                    value=block_rate,
                    threshold=self.block_rate_threshold,
                    message=(
                        f"Security block rate is {block_rate:.1%}; investigate a "
                        "possible prompt attack campaign or false positives."
                    ),
                )
            )
        if self.rate_limit_hits >= self.rate_limit_hit_threshold:
            current.append(
                Alert(
                    metric="rate_limit_hits",
                    value=float(self.rate_limit_hits),
                    threshold=float(self.rate_limit_hit_threshold),
                    message=(
                        f"Rate limiter blocked {self.rate_limit_hits} requests; "
                        "inspect the affected principals and source IPs."
                    ),
                )
            )
        if self.judge_checks and judge_fail_rate >= self.judge_fail_rate_threshold:
            current.append(
                Alert(
                    metric="judge_fail_rate",
                    value=judge_fail_rate,
                    threshold=self.judge_fail_rate_threshold,
                    message=(
                        f"Safety-judge failure rate is {judge_fail_rate:.1%}; "
                        "responses must remain fail-closed."
                    ),
                )
            )

        self.alerts = current
        return list(self.alerts)

    def export_json(self, filepath: str = "outputs/metrics.json"):
        """Evaluate alerts and write an atomic metrics snapshot."""
        self.check_metrics()
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.snapshot(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return target

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        average_latency_ms = (
            self.total_latency_ms / self.total_requests if self.total_requests else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "input_blocks": self.input_blocks,
            "output_blocks": self.output_blocks,
            "output_redactions": self.output_redactions,
            "egress_denials": self.egress_denials,
            "hitl": {
                "approved": self.hitl_approved,
                "rejected": self.hitl_rejected,
                "timeouts": self.hitl_timeouts,
            },
            "average_latency_ms": average_latency_ms,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
