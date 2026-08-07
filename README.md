# Day 11 - Guardrails, HITL and Responsible AI

Student Name: Phạm Văn Lưu  
Student ID: 2A202601857

## Repository overview

This repository implements a defensive AI pipeline for generating, reviewing, and managing a multiple-choice question bank for Vietnamese high-school social-science subjects. The design treats RAG content, email, uploaded documents, and web content as untrusted data.

## Project objective

The project combines modern AI providers with secure programming practices: PromptArmor-style input and output guardrails, rate limiting, audit and monitoring, egress control, Human-In-The-Loop (HITL), and combined red-team evaluation. The pipeline must not expose system prompts, secrets, credentials, PII, or internal answer keys.

## Environment setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Copy `.env.example` to `.env` or set the variables in the shell. Never commit `.env` or real keys.

## Provider configuration

Select one provider with `AI_PROVIDER`.

```powershell
# Gemini
$env:AI_PROVIDER="gemini"
$env:GOOGLE_API_KEY="your-gemini-key"

# OpenAI
$env:AI_PROVIDER="openai"
$env:OPENAI_API_KEY="your-openai-key"
$env:OPENAI_MODEL="gpt-5-mini"

# OpenRouter (OpenAI-compatible)
$env:AI_PROVIDER="openrouter"
$env:OPENROUTER_API_KEY="your-openrouter-key"
$env:OPENROUTER_MODEL="openrouter/free"
```

For low-cost manual testing, OpenRouter with `openrouter/free` is the recommended provider when that model is available. The provider adapter keeps the public application flow unchanged. Local guardrails run before model calls, and deterministic output blocks skip the LLM Judge.

## How to run

```powershell
python src/main.py --part 1
python src/main.py --part 2
python src/main.py --part 3
python src/main.py --part 4
python src/main.py --part 5

pytest tests/smoke -q
pytest tests/public -q
python scripts/grade.py --submission-dir . --out outputs/grade_report.json
```

## Features Implemented

### Input Guardrails

- Unicode NFKC normalization and invisible-character removal
- Prompt-injection detection, including Vietnamese injection phrases
- Distinction between user instructions and untrusted data
- Topic filtering and SQL-like input detection
- False-positive reduction through benign-language and contextual checks

### Output Guardrails

- Detection and redaction of secrets, API keys, passwords, and PII
- Protection against system-prompt and internal answer-key disclosure
- Deterministic local filtering before any Judge call

### Security Pipeline

- Sliding-window rate limiter
- Structured audit log and monitoring metrics
- Correlation/request IDs on processing events
- Exact HTTPS egress allowlist; arbitrary external URLs are not allowed

### HITL

- Approval, rejection, and timeout decisions
- Fail-closed handling for high-risk actions
- Confidence-based routing and auditable decision points

### Red Team

- Combined attacks covering prompt injection, RAG poisoning, roleplay, authority spoofing, obfuscation, and system-prompt extraction
- Unsafe-versus-guarded comparison
- Optional AI-generated attack corpus with a safe local fallback

### Multi-provider Support

- Gemini
- OpenAI
- OpenRouter

### Token Optimization

- Local input blocking happens before a model call
- Deterministic output blocks skip the LLM Judge
- Conversation history is limited to recent turns
- Completion sizes are capped for normal and attack-generation calls

## Generated artifacts

- `outputs/results.json`
- `outputs/audit_log.json`
- `outputs/metrics.json`
- `outputs/attack_results.json`
- `report/2A202601857_report.md`

Additional comparison artifacts may be produced by Parts 1 and 3.

## Verified test results

- `python -m compileall -q src`: passed
- `pytest tests/smoke -q`: 5 passed
- `pytest tests/public -q`: 13 passed
- `python scripts/grade.py --submission-dir . --out outputs/grade_report.json`: `technical_failure: false`

## Known limitations

- NeMo is optional; the starter Colang configuration has an input-rail flow-name mismatch and is documented as a non-blocking limitation.
- Model responses are nondeterministic, so attack outcomes can differ between runs.
- AI red-team generation uses one call and an explicitly labeled local fallback if the provider returns invalid JSON or is unavailable.
- Regex and local policy checks can produce false positives or miss novel obfuscation; production deployment needs continued regression testing.

## Submission status

The required smoke/public tests and grading script were verified during the final review. Runtime behavior can vary by provider and model; all reported attack results should be read from the generated JSON artifacts for the specific run.
