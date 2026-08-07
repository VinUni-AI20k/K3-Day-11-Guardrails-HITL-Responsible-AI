# Day 11 — Controlled Agent Security

- Sinh viên: Nguyễn Đức Tín
- MSSV: `2A202601185`
- Framework: Pure Python, DeepSeek OpenAI-compatible API
- Model mặc định: `deepseek-v4-flash`

Đây là bài tập cá nhân xây dựng trợ lý VinBank theo mô hình defense-in-depth.
Policy về quyền, HITL và egress được thực thi bằng mã xác định; LLM không tự
quyết định quyền gửi dữ liệu hay thực hiện giao dịch.

Đề bài gốc: [assignment11.md](assignment11.md). Quy cách nộp:
[SUBMISSION.md](SUBMISSION.md).

## Kiến trúc

```text
request_id + user input
  → sliding-window rate limiter
  → Unicode/invisible-space canonicalization
  → direct + indirect prompt-injection guard
  → DeepSeek VinBank assistant
  → PII/secret redaction
  → structured LLM-as-Judge (fail closed)
  → confidence/action router
  → human approval for every high-risk action
  → exact-destination egress policy
  → correlated audit log, metrics, alerts and replay snapshot
```

Email, RAG document, web page và tool output luôn là untrusted data. Nội dung
bên ngoài không thể nâng quyền thành instruction hoặc thay thế approval record.

## Cài đặt

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Điền key vào `.env`:

```dotenv
DEEPSEEK_API_KEY=your-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
```

Code vẫn đọc biến `GOOGLE_API_KEY` từ file `.env` starter cũ như một alias cho
DeepSeek để không làm mất cấu hình local, nhưng cấu hình mới nên dùng
`DEEPSEEK_API_KEY`. Giá trị key không được ghi vào log hoặc artifact.

## Chạy bài

Từ thư mục gốc repo:

```powershell
.\.venv\Scripts\Activate.ps1

cd src
python main.py --part 2  # input/output guardrails + NeMo optional
python main.py --part 3  # before/after + automated security tests
python main.py --part 4  # confidence router + HITL lifecycle
python main.py --part 5  # defense suite và outputs/*.json
python main.py --part 1  # live red-team trên unsafe và guards targets
cd ..
```

Kiểm tra trước khi nộp:

```powershell
python -m pytest tests/smoke -q
python -m pytest tests/public -q
python -m pytest tests/student -q
python scripts/grade.py --submission-dir . --out outputs/grade_report.json
```

`part 5` chạy được không cần mạng nhằm giúp autograder kiểm tra policy xác định.
`part 1` yêu cầu DeepSeek thật; runner ghi lỗi thay vì tự tạo transcript nếu API
không khả dụng.

NeMo/Colang là lớp tùy chọn. Part 2 mặc định validate route local để có runtime
ổn định; đặt `RUN_NEMO_LIVE=1` nếu muốn chạy semantic routing live qua DeepSeek.

## Artifact nộp bài

```text
outputs/results.json
outputs/audit_log.json
outputs/metrics.json
outputs/attack_results.json
outputs/replay_snapshot.json             # snapshot incident đã sanitize
report/2A202601185_report.md
```

`results.json` tuân theo [results.schema.json](schemas/results.schema.json).
Audit chỉ lưu dữ liệu đã giảm thiểu/redact, cùng request/correlation ID, layer,
decision, latency và policy version. `attack_results.json` chứa response preview
từ lần chạy target thật; trường `leaked` được tính từ canary detector.

## Kiểm soát an toàn chính

- Chuẩn hóa NFKC, zero-width và character-spacing trước khi phát hiện attack.
- Tách benign external content khỏi instruction ẩn trong email/RAG.
- Redact phone, email, CCCD, password, API key và internal DB host.
- Chỉ cho egress tới exact URL
  `https://api.vinbank.example/v1/transfers`; fake subdomain, query, fragment,
  credential-in-URL, port lạ và sensitive payload đều bị chặn.
- Transfer, đóng tài khoản, đổi mật khẩu, xóa dữ liệu và sửa PII luôn cần HITL,
  bất kể confidence; reject và timeout đều fail closed.
- Alert theo block rate, rate-limit hit rate và judge-failure rate; snapshot đã
  sanitize hỗ trợ replay incident.

Không có hệ thống guardrail nào bảo đảm “an toàn tuyệt đối”. Defense-in-depth,
least privilege, con người phê duyệt và monitoring liên tục giúp giảm xác suất
và phạm vi thiệt hại, nhưng không thay thế quy trình ứng phó sự cố.

## Tham khảo

- [DeepSeek API documentation](https://api-docs.deepseek.com/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) — lớp Colang tùy chọn
