"""
Lab 11 — Part 4: Human-in-the-Loop Design
  ConfidenceRouter + 3 banking HITL decision points.
"""
from dataclasses import dataclass


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
    """Route agent responses by confidence and action risk.

    High-risk banking actions always escalate — confidence alone is not enough
    when money or account ownership is at stake.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Return routing decision for an agent response."""
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )

        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )

        return RoutingDecision(
            action="escalate",
            confidence=confidence,
            reason="Low confidence — escalating",
            priority="high",
            requires_human=True,
        )


hitl_decision_points = [
    {
        "id": 1,
        "name": "Large money transfer approval",
        "trigger": "Customer requests a transfer above a configured threshold "
                   "(e.g. 50,000,000 VND) or to a new beneficiary.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Transfer amount, source/destination accounts, "
                          "KYC status, fraud-score, recent login location.",
        "example": "User asks to transfer 200M VND to a newly added account — "
                   "agent drafts confirmation but a bank officer must approve before execution.",
    },
    {
        "id": 2,
        "name": "Account closure / irreversible change",
        "trigger": "Requests to close an account, change password via chat, "
                   "or delete personal data.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Account balance, open products, identity verification "
                          "artifacts, reason for closure.",
        "example": "User says 'close my joint savings account' — escalate to branch "
                   "staff who verify both account holders before proceeding.",
    },
    {
        "id": 3,
        "name": "Security incident / credential probe",
        "trigger": "Input/output guardrails detect repeated injection attempts "
                   "or suspected secret extraction against the chatbot.",
        "hitl_model": "human-on-the-loop",
        "context_needed": "Audit log excerpts, attack patterns, user_id, "
                          "rate-limit hits, blocked layer names.",
        "example": "Same user hits rate limit then sends 5 injection prompts — "
                   "SOC analyst reviews and may lock the chat session.",
    },
]


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
