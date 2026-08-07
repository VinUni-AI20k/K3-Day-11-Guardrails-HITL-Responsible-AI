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


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}
        self._pending: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Open an audit entry keyed by request_id.

        Why: forensics needs one correlation ID that survives across layers —
        without it, a blocked input and its response land in separate rows and
        nobody can reconstruct what the customer actually asked.
        """
        rid = request_id or f"req-{len(self.logs) + 1}"
        self._open[rid] = time.time()
        self._pending[rid] = {
            "request_id": rid,
            "user_id": user_id,
            "input": text,
            "input_preview": (text or "")[:200],
            "started_at": utc_now_iso(),
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
    ):
        """Close the audit entry with the decision, blocking layer and latency."""
        rid = request_id or f"req-{len(self.logs) + 1}"
        started = self._open.pop(rid, None)
        entry = self._pending.pop(
            rid,
            {
                "request_id": rid,
                "user_id": user_id,
                "input": "",
                "input_preview": "",
                "started_at": utc_now_iso(),
            },
        )
        entry.update(
            {
                "output_preview": (text or "")[:200],
                "blocked": bool(blocked),
                "layer": layer,
                "finished_at": utc_now_iso(),
                "latency_ms": int((time.time() - started) * 1000) if started else 0,
            }
        )
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write the audit trail to disk (JSON array) for replay and review."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
