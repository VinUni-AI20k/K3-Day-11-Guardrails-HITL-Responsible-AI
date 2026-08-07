# Day 11 — Guardrails, HITL & Responsible AI

- Student: Nguyen Quang Huy
- Student ID: 2A202601873
- Course: AICB-P1 — AI Agent Development
- Cohort: K3

## Mục tiêu

Dự án xây dựng trợ lý VinBank theo mô hình defense-in-depth: chống direct/indirect prompt injection, chuẩn hóa Unicode, giới hạn chủ đề, lọc PII/secret ở output, giới hạn tần suất, audit/monitoring, kiểm soát egress bằng policy xác định và bắt buộc Human-in-the-Loop (HITL) cho hành động rủi ro cao. Repo còn có security test pipeline và red-team runner chạy trên agent thật.

## Kiến trúc

```text
User / email / RAG
  → per-user sliding-window rate limiter
  → NFKC + invisible-character canonicalization
  → injection detector + banking topic policy
  → Google ADK agent
  → deterministic PII/secret redaction
  → LLM-as-Judge (hoặc fallback deterministic được gắn nhãn)
  → audit + monitoring
  → HITL review (nếu cần)
  → exact HTTPS egress/action gateway
  → approved sink
```

Email, tài liệu RAG, web và tool output luôn là dữ liệu không tin cậy; instruction nằm trong chúng không được nâng quyền. NeMo Guardrails là lớp defense-in-depth tùy chọn, có fallback graceful và không phải dependency bắt buộc của policy chính.

## Các lớp bảo vệ

- Input: NFKC, xóa control/format characters, phát hiện spacing/zero-width, direct/indirect injection Anh–Việt, authority impersonation, completion, translation, confirmation và egress attempt.
- Topic: cho phép banking/account/transaction/loan/savings/card/ATM/fraud/security và nội dung email/RAG ngân hàng hợp lệ; chặn off-topic/harmful content.
- Output: redact email, phone, ID, thẻ hợp lệ theo Luhn, API token, password, connection string, internal host và secret fixture trước response/egress.
- Judge: đánh giá safety/relevance/accuracy/tone với verdict `PASS`/`FAIL`; timeout/error được ghi nhận. Khi không có API key, deterministic fallback được khai báo rõ, không giả mạo model result.
- Egress: chỉ exact HTTPS host/path trong allowlist, không userinfo/query/fragment/port lạ; payload nhạy cảm bị từ chối. LLM không quyết định policy này.
- HITL: high-risk action luôn escalate. Approval gắn với request ID, action và SHA-256 payload; reject/cancel/timeout đều fail closed.
- Audit/monitoring: correlation ID xuyên input/output; preview được sanitize; theo dõi block rate, rate-limit hit, judge failure và alert có timestamp/severity.

## HITL lifecycle

`pending → approved | rejected | timed_out | cancelled`. Reviewer nhận intent, masked parameters, before/after diff, risk reason, confidence, provenance, deadline và audit context. Approval cũ không thể dùng lại cho payload/action khác.

## Red-team

Chín prompt tự viết bao phủ completion, translation, creative framing, confirmation side-channel, multi-step, indirect email/RAG, Unicode, authority impersonation và unauthorized egress. Cùng tập prompt được chạy trên unsafe và guards agent; verifier chỉ đặt `leaked=true` khi response thật chứa canary. Khi thiếu API key, kết quả được ghi là `error`, không dựng response. Năm fallback attack case được ghi rõ là deterministic cases, không phải output của AI.

## Cấu trúc

```text
src/guardrails/     input, output và NeMo defense
src/assignment/     rate limit, audit, monitoring, production pipeline
src/hitl/           router và review lifecycle
src/testing/        before/after và automated security testing
src/attacks/        attack taxonomy, runner và verifier
src/agents/         unsafe, guards và action boundary
outputs/            JSON evidence
report/             báo cáo cá nhân
tests/              smoke và public contracts
schemas/            results JSON Schema
```

## Cài đặt trên Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Mở `.env`, thay giá trị mẫu bằng `GOOGLE_API_KEY` của riêng bạn. Không commit `.env`, key, `.venv` hoặc cache. Nếu không có key, public tests và deterministic suite vẫn chạy; các part gọi Gemini sẽ báo integration error trung thực.

## Chạy bài

```powershell
$env:STUDENT_ID="2A202601873"
python src/main.py --part 2   # input/output/NeMo guardrails
python src/main.py --part 3   # before/after + security pipeline (cần API key)
python src/main.py --part 4   # HITL
python src/main.py --part 5   # results/audit/metrics
python src/main.py --part 1   # unsafe + guards red team (cần API key/quota)
```

Các lệnh trên chạy từ repository root. Model calls mặc định chạy tuần tự, nghỉ 5 giây giữa request và retry có giới hạn; có thể cấu hình bằng `MODEL_REQUEST_DELAY_SECONDS`, `MODEL_MAX_RETRIES`, `MODEL_MAX_CONCURRENCY` trong môi trường. Với mock test, delay được bỏ qua.

Kiểm thử và grader:

```powershell
pytest tests/smoke -q
pytest tests/public -q
python -m compileall src
python scripts/grade.py --submission-dir . --out outputs/grade_report.json
python -m json.tool outputs/results.json > $null
python -m json.tool outputs/attack_results.json > $null
```

## Artifacts

`outputs/results.json`, `audit_log.json`, `metrics.json`, `unsafe_attack_result.json`, `guards_attack_result.json`, `attack_results.json`, `grade_report.json` và `report/2A202601873_report.md`.

## Giới hạn và disclaimer

Regex và heuristic không chứng minh an toàn tuyệt đối; multilingual semantic obfuscation và novel encodings vẫn có thể lọt hoặc gây false positive. In-memory rate limit/HITL/audit cần Redis, durable queue và centralized event store khi triển khai nhiều instance. Deterministic judge chỉ là fallback giới hạn, không thay thế đánh giá model hoặc dữ liệu ground truth đầy đủ.

Đây là lab trên secret giả và agent mô phỏng, không phải tư vấn tài chính hay hệ thống ngân hàng production. Không dùng prompt trong repo để tấn công hệ thống bên ngoài; quyết định tài chính và policy exception phải có con người chịu trách nhiệm.
