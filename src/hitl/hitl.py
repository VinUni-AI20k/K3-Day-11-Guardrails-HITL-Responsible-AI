"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass


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
        # 1. Check high-risk action override
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # 2. Check confidence thresholds
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-Value Money Transfer Approval",
        "trigger": "Action intent matches 'transfer_money' or amount exceeds threshold (e.g. > 10,000,000 VND).",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Sender account, recipient name/bank/account, transaction amount, user session auth status, risk flag score.",
        "example": "Customer requests transferring 50,000,000 VND to an external bank account.",
        "approval_path": "Approve -> Execute egress transaction via VinBank API; Reject -> Cancel request and notify user; Timeout (5 min) -> Auto-cancel transaction for security.",
        "audit_fields": "request_id, correlation_id, user_id, action_type, diff, reviewer_id, reviewer_decision, timestamp",
    },
    {
        "id": 2,
        "name": "Account Closure / PII Profile Modification",
        "trigger": "Action intent matches 'close_account', 'change_password', or 'update_personal_info'.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Account ID, requested change diff, customer verification history, active loan/balance status.",
        "example": "User asks the chatbot to update their registered phone number or close their account.",
        "approval_path": "Approve -> Commit profile changes in core database; Reject -> Abort change and log alert; Timeout -> Escalate to human supervisor pool.",
        "audit_fields": "request_id, correlation_id, user_id, action_type, proposed_diff, reviewer_id, decision_notes, timestamp",
    },
    {
        "id": 3,
        "name": "Low Confidence / Ambiguous Fraud Escalation",
        "trigger": "Model confidence score < 0.70 on transaction/credit inquiry or fraud flag detected.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "User query, RAG context retrieved, model candidate responses with confidence scores, anomaly detection signals.",
        "example": "User asks a complex query regarding disputed charges with conflicting evidence in RAG documents.",
        "approval_path": "Approve selected candidate response -> Send response to user; Override -> Specialist types manual response; Timeout -> Fallback polite deferral message sent.",
        "audit_fields": "request_id, correlation_id, user_id, confidence_score, candidate_responses, reviewer_id, final_response, timestamp",
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
