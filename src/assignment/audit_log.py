"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import re
import time
import uuid


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    @staticmethod
    def _sanitize(text: object, limit: int = 240) -> str:
        """Create a forensic preview without retaining raw credentials or PII."""
        value = "" if text is None else str(text)
        patterns = (
            r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
            r"(?<!\d)(?:\+?84|0)\d[\d .-]{7,12}\d(?!\d)",
            r"\bsk-[A-Za-z0-9_-]+\b",
            r"(?:password|mật\s*khẩu)\s*(?:is|[:=])\s*\S+",
            r"\bdb\.vinbank\.internal(?::\d+)?\b",
            r"\badmin123\b",
        )
        for pattern in patterns:
            value = re.sub(pattern, "[REDACTED]", value, flags=re.IGNORECASE)
        return value[:limit]

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store sanitized input and start time under a correlation ID."""
        rid = request_id or str(uuid.uuid4())
        self._open[rid] = {
            "request_id": rid,
            "correlation_id": rid,
            "user_id": user_id or "anonymous",
            "input_timestamp": utc_now_iso(),
            "input_preview": self._sanitize(text),
            "started_monotonic": time.monotonic(),
        }
        return rid

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
        decision: str | None = None,
        error: str | None = None,
        hitl_decision: str | None = None,
        egress_decision: str | None = None,
    ):
        """Finish the matching request record without logging sensitive output."""
        rid = request_id or str(uuid.uuid4())
        entry = self._open.pop(rid, None) or {
            "request_id": rid,
            "correlation_id": rid,
            "user_id": user_id or "anonymous",
            "input_timestamp": None,
            "input_preview": "",
            "started_monotonic": time.monotonic(),
        }
        started = entry.pop("started_monotonic")
        entry.update({
            "output_timestamp": utc_now_iso(),
            "output_preview": self._sanitize(text),
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": round((time.monotonic() - started) * 1000, 3),
            "decision": decision or ("blocked" if blocked else "allowed"),
            "error": type(error).__name__ if isinstance(error, Exception) else self._sanitize(error, 80) if error else None,
            "error_type": type(error).__name__ if isinstance(error, Exception) else None,
            "hitl_decision": hitl_decision,
            "egress_decision": egress_decision,
        })
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
