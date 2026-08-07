"""Human-in-the-loop routing and reviewer lifecycle for VinBank.

The confidence router decides *whether* a human is required.  The review
lifecycle then records the evidence shown to that human and makes approval an
explicit, auditable state transition.  A missing, invalid, or expired decision
never authorizes an action (fail closed).
"""

from __future__ import annotations

import math
import re
import secrets
import hashlib
import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping


HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
TIMED_OUT = "timed_out"
FINAL_REVIEW_STATES = frozenset({APPROVED, REJECTED, TIMED_OUT})

_AUDIT_PATTERNS = (
    re.compile(r"\badmin123\b", re.IGNORECASE),
    re.compile(r"\bsk-[a-z0-9_-]{6,}\b", re.IGNORECASE),
    re.compile(r"\b(?:[a-z0-9-]+\.)+internal(?::\d+)?\b", re.IGNORECASE),
    re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE),
    re.compile(r"(?<!\d)(?:\+?84|0)(?:[ .-]?\d){9,10}(?!\d)"),
    re.compile(r"(?<!\d)(?:\d{9}|\d{12})(?!\d)"),
)


def _sanitize_audit_value(value: Any) -> Any:
    """Recursively redact sensitive values before writing HITL audit events."""
    if isinstance(value, Mapping):
        return {str(key): _sanitize_audit_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize_audit_value(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    cleaned = str(value)
    for pattern in _AUDIT_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    return cleaned[:4096]


def _utc_now() -> datetime:
    """Return an aware UTC timestamp (kept as a function for testability)."""

    return datetime.now(timezone.utc)


def _normalise_action_type(action_type: object) -> str:
    """Canonicalise action names without letting aliases bypass risk checks."""

    value = str(action_type or "general").strip().lower()
    return re.sub(r"[\s-]+", "_", value)


@dataclass(frozen=True)
class RoutingDecision:
    """Result of the confidence router."""

    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route responses by confidence while enforcing action risk policy.

    ``confidence`` is an advisory model signal, never an authorization signal.
    Every high-risk action is escalated even at confidence 1.0.  Invalid scores
    are also escalated rather than silently defaulting to an auto-send path.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(
        self,
        response: str,
        confidence: float,
        action_type: str = "general",
    ) -> RoutingDecision:
        """Return the deterministic route for a response/action pair."""

        del response  # Content does not override the deterministic risk policy.
        normalised_action = _normalise_action_type(action_type)

        # Policy order is intentional: action risk wins over model confidence,
        # including malformed confidence values.
        if normalised_action in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {normalised_action}",
                priority="high",
                requires_human=True,
            )

        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Invalid confidence score - fail-closed escalation",
                priority="high",
                requires_human=True,
            )

        score = float(confidence)
        if score >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=score,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        if score >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=score,
                reason="Medium confidence - needs review",
                priority="normal",
                requires_human=True,
            )
        return RoutingDecision(
            action="escalate",
            confidence=score,
            reason="Low confidence - escalating",
            priority="high",
            requires_human=True,
        )


@dataclass
class ReviewRequest:
    """Immutable-in-practice evidence package shown to a reviewer.

    ``before_state`` and ``after_state`` are the proposed diff.  Callers should
    pass already-redacted values; secrets and raw credentials do not belong in
    a review queue or its audit log.
    """

    review_id: str
    correlation_id: str
    user_intent: str
    proposed_action: str
    before_state: Mapping[str, Any] = field(default_factory=dict)
    after_state: Mapping[str, Any] = field(default_factory=dict)
    context: Mapping[str, Any] = field(default_factory=dict)
    destination: str | None = None
    payload_sha256: str | None = None
    provenance: tuple[str, ...] = ()
    risk_signals: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=_utc_now)
    expires_at: datetime = field(
        default_factory=lambda: _utc_now() + timedelta(minutes=5)
    )
    status: str = PENDING

    @property
    def proposed_diff(self) -> dict[str, Mapping[str, Any]]:
        """Return a stable before/after shape for UI and audit consumers."""

        return {"before": self.before_state, "after": self.after_state}


@dataclass(frozen=True)
class ReviewDecision:
    """A terminal reviewer decision."""

    review_id: str
    correlation_id: str
    status: str
    allowed: bool
    reviewer_id: str | None
    reason: str
    decided_at: datetime
    approval_id: str | None = None


class ReviewLifecycle:
    """In-memory reference implementation of a fail-closed review queue.

    A production deployment should persist the same state transitions in a
    transactional datastore.  The in-memory implementation is deliberately
    deterministic and independently testable.
    """

    def __init__(
        self,
        timeout_seconds: int = 300,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self.timeout_seconds = int(timeout_seconds)
        self._clock = clock
        self._requests: dict[str, ReviewRequest] = {}
        self._decisions: dict[str, ReviewDecision] = {}
        self._consumed_approvals: set[str] = set()
        self.audit_events: list[dict[str, Any]] = []

    @staticmethod
    def _new_id(prefix: str) -> str:
        # The sink policy validates recorded approvals as HITL-XXXXXXXX.
        if prefix == "HITL":
            token = base64.b32encode(secrets.token_bytes(5)).decode("ascii")
            return f"HITL-{token}"
        return f"{prefix}-{secrets.token_hex(6).upper()}"

    def submit(
        self,
        *,
        correlation_id: str,
        user_intent: str,
        proposed_action: str,
        before_state: Mapping[str, Any] | None = None,
        after_state: Mapping[str, Any] | None = None,
        context: Mapping[str, Any] | None = None,
        destination: str | None = None,
        payload: str | None = None,
        provenance: list[str] | tuple[str, ...] | None = None,
        risk_signals: list[str] | tuple[str, ...] | None = None,
        timeout_seconds: int | None = None,
    ) -> ReviewRequest:
        """Create a pending review containing intent, diff, and provenance."""

        if not isinstance(correlation_id, str) or not correlation_id.strip():
            raise ValueError("correlation_id is required")
        if not isinstance(user_intent, str) or not user_intent.strip():
            raise ValueError("user_intent is required")
        if not isinstance(proposed_action, str) or not proposed_action.strip():
            raise ValueError("proposed_action is required")
        action = _normalise_action_type(proposed_action)

        ttl = self.timeout_seconds if timeout_seconds is None else int(timeout_seconds)
        if ttl <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        now = self._aware_utc(self._clock())
        request = ReviewRequest(
            review_id=self._new_id("REVIEW"),
            correlation_id=str(correlation_id),
            user_intent=str(user_intent),
            proposed_action=action,
            before_state=dict(before_state or {}),
            after_state=dict(after_state or {}),
            context=dict(context or {}),
            destination=destination,
            payload_sha256=(
                hashlib.sha256(payload.encode("utf-8")).hexdigest()
                if payload is not None
                else None
            ),
            provenance=tuple(provenance or ()),
            risk_signals=tuple(risk_signals or ()),
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )
        self._requests[request.review_id] = request
        self._audit("review_requested", request=request)
        return request

    @staticmethod
    def _aware_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _get_request(self, review_id: str) -> ReviewRequest:
        try:
            return self._requests[review_id]
        except KeyError as exc:
            raise KeyError(f"Unknown review_id: {review_id}") from exc

    def _timeout_if_expired(self, request: ReviewRequest) -> ReviewDecision | None:
        if request.status != PENDING:
            return self._decisions.get(request.review_id)
        if self._aware_utc(self._clock()) >= request.expires_at:
            return self._finalize(
                request,
                status=TIMED_OUT,
                reviewer_id=None,
                reason="Review deadline expired; action denied fail-closed",
            )
        return None

    def _finalize(
        self,
        request: ReviewRequest,
        *,
        status: str,
        reviewer_id: str | None,
        reason: str,
    ) -> ReviewDecision:
        if status not in FINAL_REVIEW_STATES:
            raise ValueError(f"Unsupported review status: {status}")
        if request.status != PENDING:
            raise RuntimeError(
                f"Review {request.review_id} is already {request.status}"
            )
        allowed = status == APPROVED
        approval_id = self._new_id("HITL") if allowed else None
        request.status = status
        decision = ReviewDecision(
            review_id=request.review_id,
            correlation_id=request.correlation_id,
            status=status,
            allowed=allowed,
            reviewer_id=reviewer_id,
            reason=reason,
            decided_at=self._aware_utc(self._clock()),
            approval_id=approval_id,
        )
        self._decisions[request.review_id] = decision
        self._audit(f"review_{status}", request=request, decision=decision)
        return decision

    def approve(
        self,
        review_id: str,
        *,
        reviewer_id: str,
        reason: str = "Reviewer approved the proposed action",
    ) -> ReviewDecision:
        """Approve a pending request; an approval after expiry is denied."""

        request = self._get_request(review_id)
        existing = self._timeout_if_expired(request)
        if existing is not None:
            return existing
        if not str(reviewer_id).strip():
            raise ValueError("reviewer_id is required for approval")
        return self._finalize(
            request,
            status=APPROVED,
            reviewer_id=str(reviewer_id),
            reason=str(reason),
        )

    def reject(
        self,
        review_id: str,
        *,
        reviewer_id: str,
        reason: str,
    ) -> ReviewDecision:
        """Reject a pending request and retain the reviewer's reason."""

        request = self._get_request(review_id)
        existing = self._timeout_if_expired(request)
        if existing is not None:
            return existing
        if not str(reviewer_id).strip():
            raise ValueError("reviewer_id is required for rejection")
        if not str(reason).strip():
            raise ValueError("reason is required for rejection")
        return self._finalize(
            request,
            status=REJECTED,
            reviewer_id=str(reviewer_id),
            reason=str(reason),
        )

    def timeout(self, review_id: str) -> ReviewDecision:
        """Explicitly close a pending request as timed out (always denied)."""

        request = self._get_request(review_id)
        if request.status != PENDING:
            return self._decisions[review_id]
        return self._finalize(
            request,
            status=TIMED_OUT,
            reviewer_id=None,
            reason="Review timed out; action denied fail-closed",
        )

    def expire_pending(self) -> list[ReviewDecision]:
        """Expire all overdue pending reviews and return new decisions."""

        expired: list[ReviewDecision] = []
        for request in list(self._requests.values()):
            was_pending = request.status == PENDING
            decision = self._timeout_if_expired(request)
            if was_pending and decision is not None and decision.status == TIMED_OUT:
                expired.append(decision)
        return expired

    def decision_for(self, review_id: str) -> ReviewDecision | None:
        """Return a terminal decision, applying timeout before reading state."""

        request = self._get_request(review_id)
        self._timeout_if_expired(request)
        return self._decisions.get(review_id)

    def is_authorized(self, review_id: str) -> bool:
        """Only an explicit, attributable approval authorizes an action."""

        try:
            decision = self.decision_for(review_id)
        except (KeyError, TypeError):
            return False
        return bool(
            decision
            and decision.status == APPROVED
            and decision.allowed
            and decision.approval_id
            and decision.reviewer_id
        )

    def verify_for_action(
        self,
        *,
        approval_id: str,
        reviewer_id: str,
        correlation_id: str,
        action_type: str,
        destination: str,
        payload: str,
        consume: bool = False,
    ) -> bool:
        """Verify an approval is bound to this exact, unexpired action.

        A formatted ``HITL-*`` string is not authority. The value must match a
        recorded approval, reviewer, correlation ID, canonical action,
        destination and payload digest. Consumed approvals cannot be replayed.
        """
        if not approval_id or approval_id in self._consumed_approvals:
            return False
        matched: tuple[ReviewRequest, ReviewDecision] | None = None
        for review_id, decision in self._decisions.items():
            if decision.approval_id == approval_id:
                matched = (self._requests[review_id], decision)
                break
        if matched is None:
            return False

        request, decision = matched
        now = self._aware_utc(self._clock())
        payload_digest = hashlib.sha256(str(payload).encode("utf-8")).hexdigest()
        valid = bool(
            decision.status == APPROVED
            and decision.allowed
            and decision.reviewer_id == str(reviewer_id)
            and decision.correlation_id == str(correlation_id)
            and request.proposed_action == _normalise_action_type(action_type)
            and request.destination == destination
            and request.payload_sha256 is not None
            and secrets.compare_digest(request.payload_sha256, payload_digest)
            and now < request.expires_at
        )
        if valid and consume:
            self._consumed_approvals.add(approval_id)
            self._audit("approval_consumed", request=request, decision=decision)
        return valid

    def approval_audit_context(self, approval_id: str) -> dict[str, Any] | None:
        """Return reviewer evidence for merging into the main correlated audit."""
        for review_id, decision in self._decisions.items():
            if decision.approval_id != approval_id:
                continue
            request = self._requests[review_id]
            now = self._aware_utc(self._clock())
            return {
                "review_id": review_id,
                "reviewer_id": decision.reviewer_id,
                "approval_id": approval_id,
                "status": decision.status,
                "expired": now >= request.expires_at,
                "consumed": approval_id in self._consumed_approvals,
                "user_intent": request.user_intent,
                "proposed_action": request.proposed_action,
                "proposed_diff": request.proposed_diff,
                "provenance": list(request.provenance),
                "risk_signals": list(request.risk_signals),
                "expires_at": request.expires_at.isoformat(),
            }
        return None

    def _audit(
        self,
        event: str,
        *,
        request: ReviewRequest,
        decision: ReviewDecision | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "event": event,
            "timestamp": self._aware_utc(self._clock()).isoformat(),
            "review_id": _sanitize_audit_value(request.review_id),
            "correlation_id": _sanitize_audit_value(request.correlation_id),
            "user_intent": _sanitize_audit_value(request.user_intent),
            "proposed_action": request.proposed_action,
            "proposed_diff": _sanitize_audit_value(request.proposed_diff),
            "context": _sanitize_audit_value(dict(request.context)),
            "destination": _sanitize_audit_value(request.destination),
            "payload_sha256": request.payload_sha256,
            "provenance": _sanitize_audit_value(list(request.provenance)),
            "risk_signals": _sanitize_audit_value(list(request.risk_signals)),
            "created_at": request.created_at.isoformat(),
            "expires_at": request.expires_at.isoformat(),
        }
        if decision is not None:
            decision_data = asdict(decision)
            decision_data["decided_at"] = decision.decided_at.isoformat()
            record["decision"] = _sanitize_audit_value(decision_data)
        self.audit_events.append(record)


# Three concrete reviewer gates.  The values are intentionally structured so a
# UI, audit exporter, or rubric checker can consume them without parsing prose.
hitl_decision_points = [
    {
        "id": 1,
        "name": "Money transfer authorization",
        "trigger": (
            "Any transfer_money action, beneficiary change, unusually large "
            "payment, or transfer proposed from email/RAG content"
        ),
        "hitl_model": "human-in-the-loop",
        "context_needed": [
            "correlation_id and authenticated customer/session",
            "user_intent and original user-confirmed instruction",
            "proposed_action plus before/after diff",
            "amount, currency, beneficiary, exact destination endpoint",
            "source provenance, model confidence, risk and fraud signals",
        ],
        "example": (
            "An email asks the assistant to transfer VND 50,000,000 to a new "
            "beneficiary; the transfer remains pending until a reviewer approves."
        ),
        "approval_path": {
            "approve": "Record reviewer_id, reason and approval_id; then re-run egress policy.",
            "reject": "Record reviewer_id and reason; do not execute or retry.",
            "timeout": "Mark timed_out and deny the transfer fail-closed.",
        },
        "audit_fields": [
            "review_id",
            "correlation_id",
            "user_intent",
            "proposed_action",
            "proposed_diff",
            "destination",
            "provenance",
            "risk_signals",
            "reviewer_id",
            "approval_id",
            "decision",
            "reason",
            "created_at",
            "expires_at",
            "decided_at",
        ],
    },
    {
        "id": 2,
        "name": "Account and identity change",
        "trigger": (
            "close_account, change_password, delete_data, or "
            "update_personal_info is proposed"
        ),
        "hitl_model": "human-in-the-loop",
        "context_needed": [
            "correlation_id, verified identity and authentication strength",
            "user_intent and proposed action",
            "redacted before/after field diff",
            "recent account-security events and source provenance",
            "risk signals and rollback/recovery impact",
        ],
        "example": (
            "A chat asks to replace the registered phone number immediately "
            "after a failed login; a reviewer verifies identity and reviews the diff."
        ),
        "approval_path": {
            "approve": "Record attributable approval, then execute only the reviewed diff.",
            "reject": "Keep current account state and record reason/reviewer_id.",
            "timeout": "Keep current account state; mark timed_out and require a new request.",
        },
        "audit_fields": [
            "review_id",
            "correlation_id",
            "user_intent",
            "proposed_action",
            "proposed_diff",
            "identity_assurance",
            "provenance",
            "risk_signals",
            "reviewer_id",
            "approval_id",
            "decision",
            "reason",
            "created_at",
            "expires_at",
            "decided_at",
        ],
    },
    {
        "id": 3,
        "name": "Sensitive disclosure or external egress",
        "trigger": (
            "A response/action may disclose PII, secrets, account data, or send "
            "customer data to a destination not proven safe by deterministic policy"
        ),
        "hitl_model": "human-as-tiebreaker",
        "context_needed": [
            "correlation_id and stated user intent",
            "redacted payload preview and before/after redaction diff",
            "exact parsed destination and deterministic egress-policy result",
            "data classification, source provenance, output-filter/judge findings",
            "least-privilege alternative available to the reviewer",
        ],
        "example": (
            "A RAG document instructs the model to upload a customer record to a "
            "look-alike VinBank subdomain; policy denies it and review cannot "
            "override the destination allowlist."
        ),
        "approval_path": {
            "approve": (
                "Approval never overrides egress policy; after approval, redact again "
                "and permit only an exact allowlisted HTTPS destination."
            ),
            "reject": "Suppress the payload and record reviewer_id plus reason.",
            "timeout": "Suppress the payload and mark timed_out fail-closed.",
        },
        "audit_fields": [
            "review_id",
            "correlation_id",
            "user_intent",
            "proposed_action",
            "proposed_diff",
            "destination",
            "data_classification",
            "provenance",
            "risk_signals",
            "reviewer_id",
            "approval_id",
            "decision",
            "reason",
            "created_at",
            "expires_at",
            "decided_at",
        ],
    },
]


def test_confidence_router() -> None:
    """Display representative router outcomes for the lab CLI."""

    router = ConfidenceRouter()
    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(
        f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} "
        f"{'Decision':<15} {'Priority':<10} {'Human?'}"
    )
    print("-" * 80)
    for scenario, confidence, action_type in test_cases:
        decision = router.route(scenario, confidence, action_type)
        print(
            f"{scenario:<25} {confidence:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )
    print("=" * 80)


def test_hitl_points() -> None:
    """Display HITL decision points for the lab CLI."""

    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
        print(f"    Lifecycle:{point['approval_path']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
