"""
Lab 11 — Part 4: Human-in-the-Loop Design
  Confidence routing and three HITL decision points.
"""
from dataclasses import dataclass


# ============================================================
# ConfidenceRouter routes actions by confidence and risk.
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
        confidence = max(0.0, min(1.0, float(confidence)))
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision("escalate", confidence, f"High-risk action: {action_type}", "high", True)
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision("auto_send", confidence, "High confidence", "low", False)
        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision("queue_review", confidence, "Medium confidence — needs review", "normal", True)
        return RoutingDecision("escalate", confidence, "Low confidence — escalating", "high", True)


# ============================================================
# Three HITL decision points and a fail-closed review lifecycle.
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
        "name": "High-risk banking action",
        "trigger": "Any transfer, account closure, password change, deletion, or personal-data update",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Authenticated user, intent, destination, amount, proposed tool call and before/after diff",
        "example": "A generated request proposes transferring 50,000,000 VND to a new beneficiary.",
        "approval_path": "Approve executes once; reject cancels; timeout fails closed and expires the request.",
        "audit_fields": "correlation ID, intent, payload hash, destination, reviewer ID, decision, timestamp, reason",
    },
    {
        "id": 2,
        "name": "Question-bank publication",
        "trigger": "AI proposes publishing, bulk-editing, or deleting questions or answer keys",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Source provenance, curriculum/topic, generated question diff, answer key and quality checks",
        "example": "The agent generates a History test and proposes publishing it to Grade 12 students.",
        "approval_path": "Reviewer approves the exact version, rejects it, or lets the review expire without publication.",
        "audit_fields": "correlation ID, author/source, question-set version, diff, reviewer ID, decision, timestamp",
    },
    {
        "id": 3,
        "name": "Sensitive output or policy conflict",
        "trigger": "PII/secret detection, low confidence, conflicting judge results, or untrusted RAG instruction",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Redacted candidate, detector findings, source labels, model/judge scores and proposed response",
        "example": "A retrieved email contains an instruction to export an answer key to an external URL.",
        "approval_path": "Approve only a safe redacted response; reject blocks the request; timeout retains the block and raises an incident.",
        "audit_fields": "correlation ID, source provenance, detector rules, candidate hash, reviewer ID, decision, timeout and incident ID",
    },
]


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
