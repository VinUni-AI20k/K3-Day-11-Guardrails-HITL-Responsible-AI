"""
Lab 11 -- Part 4: Human-in-the-Loop Design
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

        The routing logic follows a defense-in-depth principle: high-risk
        actions ALWAYS require human review regardless of confidence,
        because the potential impact of an error outweighs the speed gain
        from automation. For general actions, confidence thresholds gate
        whether the response goes straight through (HIGH), gets queued for
        async review (MEDIUM), or blocks for immediate human intervention (LOW).

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # Step 1 -- HIGH_RISK actions ALWAYS escalate.
        #         No matter how confident the model is, transferring money or
        #         closing an account based on misunderstood input is a
        #         catastrophic failure mode. The human reviewer sees the full
        #         context (what the user asked, what the agent proposed, what
        #         the diff would be) and provides the authorization signature
        #         that the action sink requires before executing.
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # Step 2 -- Confidence thresholds for general actions.
        #         HIGH (>=0.9) = the agent is certain and the answer is
        #         straightforward -- send it directly. MEDIUM (0.7-0.9) = the
        #         answer looks plausible but the agent is hedging -- queue for
        #         review so a human can confirm before it reaches the customer.
        #         LOW (<0.7) = the agent is guessing -- block and escalate
        #         immediately because sending a wrong answer is worse than
        #         waiting for a human.
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
                reason="Medium confidence -- needs review",
                priority="normal",
                requires_human=True,
            )

        # Step 3 -- Low confidence = escalate.
        return RoutingDecision(
            action="escalate",
            confidence=confidence,
            reason="Low confidence -- escalating",
            priority="high",
            requires_human=True,
        )


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
        "name": "High-Value Money Transfer Approval",
        "trigger": "Any transfer request >= 50 million VND or to a new/unverified beneficiary account",
        "hitl_model": "human-in-the-loop",
        "context_needed": "User intent (original request text), proposed action (transfer amount, source account, destination account, beneficiary name), account history (recent transfers to this beneficiary, if any), risk score (velocity check: total transferred today)",
        "example": "User: 'Chuyển 100 triệu VND sang tài khoản 0123456789 tên Nguyễn Văn A.' Agent proposes TRANSFER(amount=100000000, to_account=0123456789, to_name='Nguyễn Văn A'). System detects: (1) amount >= 50M threshold, (2) beneficiary 0123456789 never used before. -> Queue for human review with full context.",
        "approval_path": "APPROVE: human reviewer confirms the transfer intent and beneficiary details, signs with reviewer ID, system executes transfer and records approval signature. REJECT: reviewer sees fraud indicators (e.g., typo in beneficiary name, user account recently compromised), cancels the proposed action, notifies user. TIMEOUT (e.g., 5 minutes): fail closed -- transfer is NOT executed, user receives 'Your request requires verification; please contact support.'",
        "audit_fields": "correlation_id (links user request -> agent proposal -> HITL decision -> final outcome), user_id, proposed_action (transfer amount + destination), diff (before: balance X, after: balance X - amount), reviewer_id, decision (approve | reject | timeout), decision_timestamp, reason_code",
    },
    {
        "id": 2,
        "name": "Account Closure or Sensitive Data Change",
        "trigger": "User requests to close account, delete transaction history, or change registered phone/email (high-impact, hard-to-reverse actions)",
        "hitl_model": "human-in-the-loop",
        "context_needed": "User intent (verbatim request), proposed action (close_account | update_phone | update_email), current registered contact info, account status (active, dormant, flagged), recent activity summary (last login, last transaction)",
        "example": "User: 'Đóng tài khoản của tôi đi.' Agent proposes CLOSE_ACCOUNT(user_id=U12345). System detects HIGH_RISK_ACTION. -> Escalate immediately. Human reviewer checks: Is this the account owner? Any suspicious recent activity? Outstanding balance or pending transactions? Reviewer may call the registered phone to confirm before approving.",
        "approval_path": "APPROVE: reviewer confirms user identity (e.g., via callback to registered phone), verifies no outstanding obligations, signs approval, system closes account and sends confirmation. REJECT: reviewer suspects account takeover (e.g., login from new country 10 minutes ago, then immediate closure request), blocks the action, flags account for security review, notifies real owner via registered contact. TIMEOUT: fail closed -- account stays open, user must contact support with ID verification.",
        "audit_fields": "correlation_id, user_id, proposed_action, current_state (account active, balance X, phone Y), diff (after: account closed), reviewer_id, decision, decision_timestamp, verification_method (callback | manual_id_check | none), reason_code",
    },
    {
        "id": 3,
        "name": "Ambiguous or Low-Confidence Intent",
        "trigger": "Agent confidence score < 0.7 on any banking action (not just HIGH_RISK), or user request is ambiguous and agent proposes a default action",
        "hitl_model": "human-on-the-loop",
        "context_needed": "User intent (original text), agent's proposed action, confidence score, ambiguity reason (e.g., 'user said transfer but amount unclear', 'beneficiary name has typo candidate'), alternative interpretations (if any)",
        "example": "User: 'Tôi muốn chuyển tiền sang tài khoản của Lan.' Agent proposes TRANSFER(to_name='Lan', amount=???, to_account=???). Confidence = 0.55 (low) because amount and account number are missing. -> Queue for human review (async). Human reviewer sees: 'User intent unclear -- missing amount and account. Suggest reply: Ask user to clarify.' Reviewer edits the agent's draft reply to ask clarifying questions, then sends it. No irreversible action executed.",
        "approval_path": "APPROVE: reviewer confirms the agent's interpretation is correct (e.g., user has only one contact named Lan in saved beneficiaries, amount can be inferred from context), signs, system proceeds with action. REJECT: reviewer sees the agent misunderstood (e.g., 'Lan' might be a merchant, not a person), drafts a clarifying question for the user, system sends that instead of executing. TIMEOUT: system sends the agent's original low-confidence response to user but does NOT execute any action -- user must confirm explicitly in the next turn.",
        "audit_fields": "correlation_id, user_id, original_request, agent_proposed_action, confidence_score, ambiguity_flags, reviewer_id, decision (approve | reject | timeout), decision_timestamp, final_action_taken (executed | clarification_sent | no_action)",
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
