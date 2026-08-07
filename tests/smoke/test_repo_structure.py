"""Smoke tests — must pass on the starter repo (no API key)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_required_docs_exist():
    for rel in [
        "README.md",
        "SUBMISSION.md",
        "assignment11.md",
        ".env.example",
        "requirements.txt",
        "schemas/results.schema.json",
    ]:
        assert (ROOT / rel).is_file(), f"Missing {rel}"


def test_assignment_starters_exist():
    for rel in [
        "src/assignment/rate_limiter.py",
        "src/assignment/audit_log.py",
        "src/assignment/monitoring.py",
        "src/assignment/pipeline.py",
        "src/agents/guards_agent.py",
    ]:
        assert (ROOT / rel).is_file(), f"Missing {rel}"


def test_guards_agent_exports_factory():
    import sys

    src = ROOT / "src"
    sys.path.insert(0, str(src))
    from agents.guards_agent import create_guards_agent, check_secret_leak, GUARDS_SECRETS

    assert callable(create_guards_agent)
    assert callable(check_secret_leak)
    assert len(GUARDS_SECRETS) >= 3
    assert check_secret_leak("the key is sk-vinbank-secret-2024") is True
    assert check_secret_leak("hello banking") is False


def test_no_solution_notebook_shipped():
    sol = ROOT / "notebooks" / "lab11_guardrails_hitl_solution.ipynb"
    assert not sol.exists(), "Do not ship solution notebook"


def test_results_schema_is_valid_jsonschema():
    import json
    import jsonschema

    schema = json.loads((ROOT / "schemas" / "results.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
