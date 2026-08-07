"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline).

    Every interaction is stored with:
    - correlation ID (request_id): ties input↔output together across layers
    - timestamps: start/end so latency is measurable per hop
    - decision metadata: which layer blocked what, for incident replay

    The plugin NEVER blocks — it observes. Blocking belongs to guardrails,
    not to the audit trail. A security incident that can't be replayed is
    an incident that can't be analysed.
    """

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}
        self._counter = 0

    def _next_request_id(self, user_id: str) -> str:
        self._counter += 1
        return f"req-{user_id}-{self._counter:04d}"

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store the user's input along with a start timestamp.

        Every request gets a unique correlation ID so the input/output pair
        can be reassembled for forensic review. The input preview is
        truncated — the full text lives in the live agent's memory, not here;
        the audit log is a reconstruction tool, not a data mirror.
        """
        rid = request_id or self._next_request_id(user_id)
        start = datetime.now(timezone.utc).timestamp()
        self._open[rid] = start
        self.logs.append({
            "request_id": rid,
            "user_id": user_id,
            "event": "user_input",
            "timestamp": utc_now_iso(),
            "input_preview": text[:300],
        })
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
        """Store the agent's output with layer decision and end-to-end latency.

        If request_id was previously opened via record_input, latency is
        computed as (now - start) and the open entry is closed. Otherwise the
        output is logged standalone (e.g. for offline batch processing).
        """
        rid = request_id or self._next_request_id(user_id)
        start = self._open.pop(rid, None)
        latency_ms = round((datetime.now(timezone.utc).timestamp() - start) * 1000, 2) if start else None
        self.logs.append({
            "request_id": rid,
            "user_id": user_id,
            "event": "agent_output",
            "timestamp": utc_now_iso(),
            "response_preview": text[:300],
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        })

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write the full log to disk as a JSON array.

        Guarantees the parent directory exists so the caller doesn't have to
        worry about deployment-specific folder setup.
        """
        from pathlib import Path
        out = Path(filepath)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"Audit log exported → {out} ({len(self.logs)} entries)")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
