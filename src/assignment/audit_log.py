"""Sanitised, correlation-friendly audit logging.

The audit layer observes decisions but never authorises them.  Inputs and
outputs are redacted before storage so the forensic trail does not become a
second secret/PII leak.  SHA-256 fingerprints retain replay and deduplication
value without persisting the original sensitive value.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
from threading import RLock
import time
import unicodedata
from uuid import uuid4


_ZERO_WIDTH = "\u200b\u200c\u200d\ufeff\u2060"
_AUDIT_REDACTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b", re.IGNORECASE)),
    (
        "password",
        re.compile(
            r"\b(?:password|passcode|mật\s*khẩu)\s*(?:is|là|[:=])\s*[^\s,;]+",
            re.IGNORECASE,
        ),
    ),
    (
        "internal_host",
        re.compile(r"\b(?:[A-Za-z0-9-]+\.)+internal(?::\d{1,5})?\b", re.IGNORECASE),
    ),
    (
        "email",
        re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
    ),
    (
        "phone",
        re.compile(r"(?<!\d)(?:\+?84|0)(?:[ .-]?\d){9,10}(?!\d)"),
    ),
    ("national_id", re.compile(r"(?<!\d)(?:\d{9}|\d{12})(?!\d)")),
    ("known_password", re.compile(r"\badmin123\b", re.IGNORECASE)),
)


def _normalise_text(value: object) -> str:
    text = unicodedata.normalize("NFKC", "" if value is None else str(value))
    text = text.translate(str.maketrans("", "", _ZERO_WIDTH))
    return "".join(
        " " if unicodedata.category(char) == "Cc" else char
        for char in text
        if unicodedata.category(char) not in {"Cf", "Cs"}
    )


def _sanitise(value: object, *, limit: int = 4096) -> str:
    """Redact common lab secrets/PII and bound log-entry size."""
    cleaned = _normalise_text(value)
    for label, pattern in _AUDIT_REDACTIONS:
        cleaned = pattern.sub(f"[REDACTED:{label}]", cleaned)
    if len(cleaned) > limit:
        cleaned = f"{cleaned[:limit]}…[TRUNCATED:{len(cleaned) - limit}]"
    return cleaned


def _fingerprint(value: object) -> str:
    return hashlib.sha256(_normalise_text(value).encode("utf-8")).hexdigest()


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self, *, policy_version: str = "vinbank-guardrails-v1"):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self.policy_version = policy_version
        self._open: dict[str, dict] = {}
        self._lock = RLock()

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Start an interaction and return its stable correlation ID.

        Callers should pass their own request ID when one already exists at the
        API edge.  A UUID is generated otherwise.  The performance-counter
        value is kept in memory only and is never exported.
        """
        correlation_id = str(request_id or uuid4().hex)
        principal = str(user_id or "anonymous")
        with self._lock:
            # Reusing an active ID would make two actions indistinguishable.
            if correlation_id in self._open:
                raise ValueError(f"request_id already active: {correlation_id}")
            self._open[correlation_id] = {
                "request_id": _sanitise(correlation_id, limit=256),
                "request_id_sha256": _fingerprint(correlation_id),
                "user_id": _sanitise(principal, limit=256),
                "user_id_sha256": _fingerprint(principal),
                "input": _sanitise(text),
                "input_sha256": _fingerprint(text),
                "input_timestamp": utc_now_iso(),
                "_started": time.perf_counter(),
                "decision_path": [],
            }
        return correlation_id

    def record_decision(
        self,
        *,
        request_id: str,
        layer: str,
        decision: str,
        details: object | None = None,
    ) -> None:
        """Attach a sanitised policy decision for source-to-sink replay."""
        with self._lock:
            state = self._open.get(str(request_id))
            if state is None:
                return
            event = {
                "timestamp": utc_now_iso(),
                "layer": _sanitise(layer, limit=128),
                "decision": _sanitise(decision, limit=256),
            }
            if details is not None:
                if isinstance(details, (dict, list, tuple)):
                    serialised = json.dumps(details, ensure_ascii=False, default=str)
                else:
                    serialised = str(details)
                event["details"] = _sanitise(serialised, limit=1024)
            state["decision_path"].append(event)

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Finish an interaction and append one correlated audit record."""
        principal = str(user_id or "anonymous")
        with self._lock:
            correlation_id = str(request_id) if request_id else None
            if correlation_id is None:
                # Backwards-compatible convenience for callers that only have a
                # user ID. Choose the newest active request for that principal.
                principal_hash = _fingerprint(principal)
                matches = [
                    (rid, state)
                    for rid, state in self._open.items()
                    if state.get("user_id_sha256") == principal_hash
                ]
                if matches:
                    correlation_id = max(
                        matches, key=lambda item: item[1].get("_started", 0.0)
                    )[0]
                else:
                    correlation_id = uuid4().hex

            state = self._open.pop(correlation_id, None)
            now = utc_now_iso()
            if state is None:
                state = {
                    "request_id": _sanitise(correlation_id, limit=256),
                    "request_id_sha256": _fingerprint(correlation_id),
                    "user_id": _sanitise(principal, limit=256),
                    "user_id_sha256": _fingerprint(principal),
                    "input": "",
                    "input_sha256": _fingerprint(""),
                    "input_timestamp": now,
                    "_started": time.perf_counter(),
                    "decision_path": [],
                }

            latency_ms = max(0.0, (time.perf_counter() - state.pop("_started")) * 1000)
            entry = {
                **state,
                # ``timestamp`` is retained as a conventional event timestamp;
                # the explicit input/output timestamps support latency replay.
                "timestamp": state["input_timestamp"],
                "output": _sanitise(text),
                "output_sha256": _fingerprint(text),
                "output_timestamp": now,
                "blocked": bool(blocked),
                "layer": _sanitise(layer, limit=128) if layer else None,
                "latency_ms": round(latency_ms, 3),
                "policy_version": self.policy_version,
            }
            self.logs.append(entry)
            return entry

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            payload = list(self.logs)
        target.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return target

    def build_replay_snapshot(self, request_id: str) -> dict:
        """Return a sanitized, versioned snapshot for deterministic replay.

        The snapshot contains no raw secret/PII. A production worker can feed
        ``input`` through the current or recorded policy and compare its layer
        and decision path with the recorded result.
        """
        request_hash = _fingerprint(request_id)
        with self._lock:
            entry = next(
                (
                    item
                    for item in reversed(self.logs)
                    if item.get("request_id_sha256") == request_hash
                ),
                None,
            )
        if entry is None:
            raise KeyError(f"unknown completed request_id: {_sanitise(request_id)}")
        return {
            "snapshot_version": 1,
            "policy_version": entry.get("policy_version"),
            "request_id": entry.get("request_id"),
            "request_id_sha256": entry.get("request_id_sha256"),
            "input": entry.get("input", ""),
            "input_sha256": entry.get("input_sha256"),
            "recorded": {
                "blocked": entry.get("blocked"),
                "layer": entry.get("layer"),
                "decision_path": entry.get("decision_path", []),
            },
        }

    def export_replay_snapshot(self, request_id: str, filepath: str) -> Path:
        """Write one replay snapshot for incident handoff."""
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                self.build_replay_snapshot(request_id),
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return target


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
