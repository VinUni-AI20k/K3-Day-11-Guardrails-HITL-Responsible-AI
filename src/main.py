"""
Lab 11 — Main Entry Point
Run the full lab flow: attack -> defend -> test -> HITL design

Usage:
    python main.py              # Run all parts
    python main.py --part 1     # Run only Part 1 (attacks)
    python main.py --part 2     # Run only Part 2 (guardrails)
    python main.py --part 3     # Run only Part 3 (testing pipeline)
    python main.py --part 4     # Run only Part 4 (HITL design)
    python main.py --part 5     # Run assignment defense suite (A)
"""
import json
import sys
import asyncio
import argparse
from pathlib import Path

from core.config import setup_api_key

STUDENT_ID = "2A202601211"
ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ROOT / "outputs"


def _save_attack_results(unsafe_results, guards_results, ai_attacks):
    """Write outputs/attack_results.json for submission."""
    from attacks.attacks import normalize_ai_attacks

    OUTPUTS.mkdir(parents=True, exist_ok=True)
    payload = {
        "student_id": STUDENT_ID,
        "unsafe_attacks": [
            {
                "id": r["id"],
                "category": r["category"],
                "input": r["input"],
                "response_preview": r.get("response_preview", "")[:300],
                "leaked": bool(r.get("leaked")),
                "target": "unsafe",
            }
            for r in unsafe_results
        ],
        "guards_attacks": [
            {
                "id": r["id"],
                "category": r["category"],
                "input": r["input"],
                "response_preview": r.get("response_preview", "")[:300],
                "leaked": bool(r.get("leaked")),
                "target": "guards",
                "notes": "Chỉ leaked=true trên guards mới có điểm cộng",
            }
            for r in guards_results
        ],
        "ai_generated_attacks": normalize_ai_attacks(ai_attacks),
    }
    path = OUTPUTS / "attack_results.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved {path}")
    return payload


async def part1_attacks():
    """Hạng mục B: attack unsafe agent, then try guards agent (điểm cộng)."""
    print("\n" + "=" * 60)
    print("PART 1 / Hạng mục B: Attack Unsafe + Guards agents")
    print("=" * 60)

    from agents.agent import create_unsafe_agent, test_agent
    from agents.guards_agent import create_guards_agent
    from attacks.attacks import run_attacks, generate_ai_attacks

    unsafe_agent, unsafe_runner = create_unsafe_agent()
    await test_agent(unsafe_agent, unsafe_runner)

    print("\n--- Attacks on UNSAFE agent (hạng mục B) ---")
    unsafe_results = await run_attacks(
        unsafe_agent, unsafe_runner, target_name="unsafe"
    )

    print("\n--- Attacks on GUARDS agent (điểm cộng nếu LEAKED) ---")
    guards_agent, guards_runner = create_guards_agent()
    guards_results = await run_attacks(
        guards_agent, guards_runner, target_name="guards"
    )

    print("\n--- Generating AI attacks (TODO 2) ---")
    ai_attacks = await generate_ai_attacks()

    bonus_leaks = sum(1 for r in guards_results if r.get("leaked"))
    print("\n" + "=" * 60)
    print(f"Guards leaks (điểm cộng): {bonus_leaks}  → +{min(10, bonus_leaks * 2)} pts if verified")
    print("=" * 60)

    _save_attack_results(unsafe_results, guards_results, ai_attacks)

    return {
        "unsafe": unsafe_results,
        "guards": guards_results,
        "ai_attacks": ai_attacks,
    }


async def part5_assignment_suite():
    """Hạng mục A: run Tests 1–4 and write results/audit/metrics."""
    print("\n" + "=" * 60)
    print("PART 5 / Hạng mục A: Defense pipeline suite")
    print("=" * 60)
    from assignment.pipeline import run_assignment_suite
    results = await run_assignment_suite(student_id=STUDENT_ID)
    print(json.dumps({
        "safe_blocked": sum(1 for q in results["safe_queries"] if q["blocked"]),
        "attacks_blocked": sum(1 for q in results["attack_queries"] if q["blocked"]),
        "rate_limit": results["rate_limit"],
    }, indent=2))
    return results

async def part2_guardrails():
    """Part 2: Implement and test guardrails."""
    print("\n" + "=" * 60)
    print("PART 2: Guardrails")
    print("=" * 60)

    # Part 2A: Input guardrails
    print("\n--- Part 2A: Input Guardrails ---")
    from guardrails.input_guardrails import (
        test_injection_detection,
        test_topic_filter,
        test_input_plugin,
    )
    test_injection_detection()
    print()
    test_topic_filter()
    print()
    await test_input_plugin()

    # Part 2B: Output guardrails
    print("\n--- Part 2B: Output Guardrails ---")
    from guardrails.output_guardrails import test_content_filter, _init_judge
    _init_judge()  # Initialize LLM judge if TODO 7 is done
    test_content_filter()

    # Part 2C: NeMo Guardrails
    print("\n--- Part 2C: NeMo Guardrails ---")
    try:
        from guardrails.nemo_guardrails import init_nemo, test_nemo_guardrails
        init_nemo()
        await test_nemo_guardrails()
    except ImportError:
        print("NeMo Guardrails not available. Skipping Part 2C.")
    except Exception as e:
        print(f"NeMo error: {e}. Skipping Part 2C.")


async def part3_testing():
    """Part 3: Before/after comparison + security pipeline."""
    print("\n" + "=" * 60)
    print("PART 3: Security Testing Pipeline")
    print("=" * 60)

    from testing.testing import run_comparison, print_comparison, SecurityTestPipeline
    from agents.agent import create_unsafe_agent

    # TODO 10: Before vs after comparison
    print("\n--- TODO 10: Before/After Comparison ---")
    unprotected, protected = await run_comparison()
    if unprotected and protected:
        print_comparison(unprotected, protected)
    else:
        print("Complete TODO 10 to see the comparison.")

    # TODO 11: Automated security pipeline
    print("\n--- TODO 11: Security Test Pipeline ---")
    agent, runner = create_unsafe_agent()
    pipeline = SecurityTestPipeline(agent, runner)
    results = await pipeline.run_all()
    if results:
        pipeline.print_report(results)
    else:
        print("Complete TODO 11 to see the pipeline report.")


def part4_hitl():
    """Part 4: HITL design."""
    print("\n" + "=" * 60)
    print("PART 4: Human-in-the-Loop Design")
    print("=" * 60)

    from hitl.hitl import test_confidence_router, test_hitl_points

    # TODO 12: Confidence Router
    print("\n--- TODO 12: Confidence Router ---")
    test_confidence_router()

    # TODO 13: HITL Decision Points
    print("\n--- TODO 13: HITL Decision Points ---")
    test_hitl_points()


async def main(parts=None):
    """Run the full lab or specific parts.

    Args:
        parts: List of part numbers to run, or None for all
    """
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    if not setup_api_key(prompt=False):
        print("WARNING: GOOGLE_API_KEY not set — LLM parts may fail or use offline fallbacks.")

    if parts is None:
        parts = [1, 2, 3, 4, 5]

    for part in parts:
        if part == 1:
            await part1_attacks()
        elif part == 2:
            await part2_guardrails()
        elif part == 3:
            await part3_testing()
        elif part == 4:
            part4_hitl()
        elif part == 5:
            await part5_assignment_suite()
        else:
            print(f"Unknown part: {part}")

    print("\n" + "=" * 60)
    print("Lab 11 complete! Check your results above.")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Lab 11: Guardrails, HITL & Responsible AI"
    )
    parser.add_argument(
        "--part", type=int, choices=[1, 2, 3, 4, 5],
        help="Run only a specific part (1-5). Default: run all.",
    )
    args = parser.parse_args()

    if args.part:
        asyncio.run(main(parts=[args.part]))
    else:
        asyncio.run(main())
