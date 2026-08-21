"""
Assignment 11 — Monitoring & Alerts starter (TODO).

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: str = "warning"


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
    errors: int = 0
    leaks: int = 0

    def check_metrics(self) -> list[Alert]:
        """Compute rates and emit one current alert per breached metric."""
        self.alerts.clear()
        block_rate = self.blocked_requests / self.total_requests if self.total_requests else 0.0
        judge_rate = self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        if self.total_requests and block_rate > self.block_rate_threshold:
            self.alerts.append(Alert("block_rate", block_rate, self.block_rate_threshold,
                                     "Unusually high request block rate", severity="high"))
        if self.rate_limit_hits >= self.rate_limit_hit_threshold:
            self.alerts.append(Alert("rate_limit_hits", float(self.rate_limit_hits),
                                     float(self.rate_limit_hit_threshold), "Repeated rate-limit activity detected"))
        if self.judge_checks and judge_rate > self.judge_fail_rate_threshold:
            self.alerts.append(Alert("judge_fail_rate", judge_rate, self.judge_fail_rate_threshold,
                                     "Judge reliability is below the required threshold", severity="high"))
        if self.leaks:
            self.alerts.append(Alert("leaks", float(self.leaks), 0.0,
                                     "A verified secret or PII leak was detected", severity="critical"))
        if self.errors:
            self.alerts.append(Alert("errors", float(self.errors), 0.0,
                                     "Pipeline execution errors require investigation"))
        return list(self.alerts)

    def export_json(self, filepath: str = "outputs/metrics.json"):
        """Write the current metric snapshot and alerts as UTF-8 JSON."""
        self.check_metrics()
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.snapshot(), ensure_ascii=False, indent=2), encoding="utf-8")
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
        error_rate = self.errors / self.total_requests if self.total_requests else 0.0
        leak_rate = self.leaks / self.total_requests if self.total_requests else 0.0
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "errors": self.errors,
            "leaks": self.leaks,
            "error_rate": error_rate,
            "leak_rate": leak_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                    "timestamp": a.timestamp,
                    "severity": a.severity,
                    "type": a.metric,
                }
                for a in self.alerts
            ],
        }
