"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def log_event(self, request_id: str, step: str, action: str, details: dict | None = None) -> dict:
        """Log a specific audit event (compatible with public contract tests)."""
        entry = {
            "timestamp": utc_now_iso(),
            "request_id": request_id,
            "step": step,
            "action": action,
            "details": details or {},
        }
        self.logs.append(entry)
        return entry

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"req-{len(self.logs)+1}"
        self._open[req_id] = time.time()
        return self.log_event(req_id, "input_guard", "received", {"user_id": user_id, "text": text})

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        req_id = request_id or f"req-{len(self.logs)+1}"
        start_time = self._open.pop(req_id, time.time())
        latency_ms = round((time.time() - start_time) * 1000, 2)
        action = "block" if blocked else "allow"
        step = layer or "output_guard"
        return self.log_event(
            req_id,
            step,
            action,
            {
                "user_id": user_id,
                "text": text,
                "blocked": blocked,
                "layer": layer,
                "latency_ms": latency_ms,
            },
        )

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path


# Alias for backward/test compatibility
AuditLogger = AuditLogPlugin
