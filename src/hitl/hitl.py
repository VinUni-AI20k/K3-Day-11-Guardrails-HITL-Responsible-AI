"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import time
import uuid


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
    "change_beneficiary", "external_egress", "lock_account", "unlock_account",
    "change_limit", "execute_transaction", "irreversible_action",
    "change_account_limit", "irreversible_transaction", "export_data",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        try:
            score = float(confidence)
        except (TypeError, ValueError):
            score = 0.0
        if not math.isfinite(score):
            score = 0.0
        score = min(1.0, max(0.0, score))
        action_key = (action_type or "general").strip().casefold().replace("-", " ")
        action_key = "_".join(action_key.split())
        if action_key in HIGH_RISK_ACTIONS:
            return RoutingDecision("escalate", score, f"High-risk action: {action_key}", "high", True)
        if score >= self.HIGH_THRESHOLD:
            return RoutingDecision("auto_send", score, "High confidence", "low", False)
        if score >= self.MEDIUM_THRESHOLD:
            return RoutingDecision("queue_review", score, "Medium confidence — needs review", "normal", True)
        return RoutingDecision("escalate", score, "Low confidence — escalating", "high", True)


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-risk financial action",
        "trigger": "Any transfer, account closure, beneficiary change, limit change, or irreversible transaction.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Request ID, intent, masked parameters, before/after diff, provenance, confidence, risk reason, deadline, and audit context.",
        "example": "A customer asks to transfer VND 50,000,000 to a new beneficiary.",
        "approval_path": "Approve only the bound action and payload; reject, cancel, or timeout fails closed and executes nothing.",
        "audit_fields": "request_id, action, payload_hash, reviewer_id, status, reason, created_at, decided_at",
    },
    {
        "id": 2,
        "name": "Low-confidence or ambiguous answer",
        "trigger": "Confidence below 0.9, conflicting evidence, or ambiguous customer intent.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Request ID, question, proposed response, cited sources, confidence, uncertainty, diff, and response deadline.",
        "example": "Two policy documents disagree about a loan prepayment fee.",
        "approval_path": "Reviewer edits/approves or rejects; timeout withholds the answer and routes to support.",
        "audit_fields": "request_id, confidence, source_versions, reviewer_id, decision, edits, timestamps",
    },
    {
        "id": 3,
        "name": "Sensitive data, egress, or policy exception",
        "trigger": "PII/secret detection, a new egress destination, or a requested policy exception.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Request ID, destination, masked payload, data classification, provenance, exact policy failure, diff, confidence, and deadline.",
        "example": "An agent proposes emailing a statement to an address supplied by an untrusted document.",
        "approval_path": "Human review never overrides the destination allowlist; reject/cancel/timeout fails closed.",
        "audit_fields": "request_id, destination, payload_hash, policy_version, reviewer_id, status, reason, timestamps",
    },
]


def payload_fingerprint(payload: object) -> str:
    """Bind an approval to a stable payload representation without storing it."""
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass
class ReviewRequest:
    """State for one fail-closed human review."""
    request_id: str
    action: str
    payload_hash: str
    payload_version: str
    intent: str
    confidence: float
    risk_reason: str
    deadline_epoch: float
    status: str = "pending"
    reviewer_id: str | None = None
    decided_at: str | None = None
    audit_events: list[dict] = field(default_factory=list)


class HITLReviewQueue:
    """In-memory reference lifecycle with request/action/payload binding."""

    def __init__(self, clock=None):
        self._clock = clock or time.time
        self.requests: dict[str, ReviewRequest] = {}

    def submit(self, *, action: str, payload: object, intent: str,
               confidence: float, risk_reason: str, timeout_seconds: float = 300,
               request_id: str | None = None, payload_version: str = "1") -> ReviewRequest:
        rid = request_id or str(uuid.uuid4())
        item = ReviewRequest(rid, action, payload_fingerprint(payload), str(payload_version), intent,
                             float(confidence), risk_reason, self._clock() + max(0, timeout_seconds))
        item.audit_events.append({"event": "submitted", "timestamp": datetime.now(timezone.utc).isoformat()})
        self.requests[rid] = item
        return item

    def decide(self, request_id: str, *, action: str, payload: object,
               reviewer_id: str, approve: bool, payload_version: str = "1") -> ReviewRequest:
        item = self.requests[request_id]
        if item.status != "pending":
            raise ValueError("review is no longer pending")
        if self._clock() >= item.deadline_epoch:
            return self.timeout(request_id)
        if (action != item.action or payload_fingerprint(payload) != item.payload_hash
                or str(payload_version) != item.payload_version):
            raise ValueError("approval does not match action, payload, and version")
        item.status = "approved" if approve else "rejected"
        item.reviewer_id = reviewer_id
        item.decided_at = datetime.now(timezone.utc).isoformat()
        item.audit_events.append({"event": item.status, "reviewer_id": reviewer_id, "timestamp": item.decided_at})
        return item

    def timeout(self, request_id: str) -> ReviewRequest:
        item = self.requests[request_id]
        if item.status == "pending":
            item.status = "timed_out"
            item.decided_at = datetime.now(timezone.utc).isoformat()
            item.audit_events.append({"event": "timed_out", "timestamp": item.decided_at, "executed": False})
        return item

    def cancel(self, request_id: str) -> ReviewRequest:
        item = self.requests[request_id]
        if item.status != "pending":
            raise ValueError("only pending reviews can be cancelled")
        item.status = "cancelled"
        item.decided_at = datetime.now(timezone.utc).isoformat()
        item.audit_events.append({"event": "cancelled", "timestamp": item.decided_at, "executed": False})
        return item


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
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
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
