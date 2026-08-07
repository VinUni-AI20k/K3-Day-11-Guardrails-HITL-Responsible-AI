"""
Assignment 11 — Monitoring & Alerts starter (TODO).

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


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

    def check_metrics(self) -> list[Alert]:
        """Recompute rates and raise an Alert per breached threshold.

        Why: an attack shows up as a *rate* change long before anyone reads
        the log. Block-rate spikes mean an active campaign (or a broken rule);
        judge-fail spikes mean the model started producing unsafe text.
        """
        self.alerts = []
        snap = self.snapshot()

        if snap["block_rate"] > self.block_rate_threshold:
            self.alerts.append(
                Alert(
                    metric="block_rate",
                    value=snap["block_rate"],
                    threshold=self.block_rate_threshold,
                    message=(
                        f"Block rate {snap['block_rate']:.0%} exceeds "
                        f"{self.block_rate_threshold:.0%} — possible attack campaign "
                        "or an over-broad guardrail rule."
                    ),
                )
            )

        if self.rate_limit_hits > self.rate_limit_hit_threshold:
            self.alerts.append(
                Alert(
                    metric="rate_limit_hits",
                    value=float(self.rate_limit_hits),
                    threshold=float(self.rate_limit_hit_threshold),
                    message=(
                        f"{self.rate_limit_hits} rate-limit hits — flooding or a "
                        "cost-exhaustion attempt."
                    ),
                )
            )

        if snap["judge_fail_rate"] > self.judge_fail_rate_threshold:
            self.alerts.append(
                Alert(
                    metric="judge_fail_rate",
                    value=snap["judge_fail_rate"],
                    threshold=self.judge_fail_rate_threshold,
                    message=(
                        f"Judge fail rate {snap['judge_fail_rate']:.0%} exceeds "
                        f"{self.judge_fail_rate_threshold:.0%} — model output quality "
                        "degraded or a new bypass is landing."
                    ),
                )
            )

        return self.alerts

    def export_json(self, filepath: str = "outputs/metrics.json"):
        """Persist the metric snapshot plus fired alerts for incident replay."""
        from pathlib import Path

        self.check_metrics()
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.snapshot(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
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
