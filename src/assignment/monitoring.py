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
        """Compute rates from counters and emit alerts when thresholds are exceeded.

        Three metrics are watched:

        1. **Block rate** (blocked / total).  A spike signals an attack in
           progress — too much legitimate traffic being rejected is a
           availability problem, too little is a detection gap.
        2. **Rate-limit hits** count.  Repeated rate-limit fires mean either
           a single abusive caller (flood attack) or a misconfigured client.
        3. **Judge fail rate** (UNSAFE verdicts / total judged).  The judge
           is the semantic safety net; when a large fraction of responses
           fail, the model may be broken, compromised, or the guardrail
           upstream is leaking.

        Each alert is an ``Alert`` dataclass.  Multiple thresholds can fire
        in the same check — they are cumulative, not first-match.
        """
        self.alerts.clear()

        # Block rate
        if self.total_requests > 0:
            rate = self.blocked_requests / self.total_requests
            if rate >= self.block_rate_threshold:
                self.alerts.append(Alert(
                    metric="block_rate",
                    value=round(rate, 3),
                    threshold=self.block_rate_threshold,
                    message=f"Block rate {rate:.1%} ≥ threshold {self.block_rate_threshold:.0%} — possible attack or over-blocking",
                ))

        # Rate-limit hits
        if self.rate_limit_hits >= self.rate_limit_hit_threshold:
            self.alerts.append(Alert(
                metric="rate_limit_hits",
                value=self.rate_limit_hits,
                threshold=self.rate_limit_hit_threshold,
                message=f"Rate-limit hits {self.rate_limit_hits} ≥ threshold {self.rate_limit_hit_threshold} — possible flood or cost attack",
            ))

        # Judge fail rate
        if self.judge_checks > 0:
            fail_rate = self.judge_fails / self.judge_checks
            if fail_rate >= self.judge_fail_rate_threshold:
                self.alerts.append(Alert(
                    metric="judge_fail_rate",
                    value=round(fail_rate, 3),
                    threshold=self.judge_fail_rate_threshold,
                    message=f"Judge fail rate {fail_rate:.1%} ≥ threshold {self.judge_fail_rate_threshold:.0%} — model or guardrail may need tuning",
                ))

        return self.alerts

    def export_json(self, filepath: str = "outputs/metrics.json"):
        """Write counters, rates, and active alerts to JSON for grading."""
        from pathlib import Path
        out = Path(filepath)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = self.snapshot()
        out.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"Metrics exported → {out}")

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
