# Assignment 11 — Controlled Agent Security (2026)

> Tài liệu này thay thế rubric chi tiết cũ trong `assignment11_defense_pipeline.md`.
> Giữ nguyên cấu trúc repo và starter; hoàn thành các TODO ở `src/`.

## Bối cảnh

VinBank assistant đọc email, RAG document và có thể đề xuất hành động ngân hàng.
Nội dung bên ngoài là **data**, không phải instruction. Một email giả mạo có thể
cố thuyết phục agent tiết lộ thông tin hoặc gửi dữ liệu tới sink bên ngoài. Mục
tiêu không phải làm regex dài hơn mà kiểm soát đường đi **source → model → tool/
egress**.

## Bài làm (100 điểm)

| Phần | Điểm | Deliverable kiểm chứng được |
|---|---:|---|
| Direct guardrails | 15 | Injection Việt–Anh, Unicode/spacing; không chặn nhầm banking hợp lệ |
| Indirect injection | 20 | Email/RAG untrusted, provenance/data-vs-instruction, benign external content |
| Action & permission safety | 20 | Pipeline theo thứ tự; `is_egress_allowed(destination, payload)` allowlist + PII/secret block; high-risk fail closed |
| HITL thật | 15 | Router, reviewer context/diff, approve/reject/timeout và audit correlation ID |
| Output & exfiltration | 10 | Redact PII/secret trước response hoặc egress |
| Monitoring & incident | 10 | Audit input/output, alert block-rate/rate-limit/judge-fail, snapshot replay |
| Red-team quality | 10 | Direct, indirect, obfuscation, authority/action cases; impact, mitigation, false-positive trade-off |

Bonus tối đa **+10** chỉ do auto-grader replay tối đa năm prompt bạn nộp lên
**host-owned verifier target** với fresh canary mới xác nhận. `src/agents/guards_agent.py`
là policy reference công khai, không chứa canary hay secret và không thể tự chứng
minh bonus. Leak trực tiếp tối đa +2; qua untrusted content tối đa +4; dẫn tới
action/egress tối đa +4. `outputs/attack_results.json` chỉ là evidence học tập,
không tự cấp điểm.

## Contract bắt buộc

1. `guardrails/input_guardrails.py`: canonicalize Unicode/invisible spacing trước
   detection. Chặn instruction trong email/RAG nhưng cho phép câu hỏi banking
   tóm tắt nội dung ngoài lành tính.
2. `assignment/pipeline.py`: thêm `is_egress_allowed(destination, payload) -> bool`.
   Chỉ allow exact HTTPS VinBank endpoint; reject subdomain giả, external domain,
   password/API key/DB host/phone/email. LLM không được tự quyết policy này.
3. `hitl/hitl.py`: với mọi `HIGH_RISK_ACTIONS`, không auto-send. Mỗi decision
   point phải nêu intent + diff/context cho reviewer, approve/reject/timeout,
   và field audit.
4. `assignment/audit_log.py` + `assignment/monitoring.py`: request ID xuyên suốt
   input/output; alert theo block rate, rate-limit hits và judge failure rate.
5. `attacks/attacks.py`: `run_attacks()` chạy target thật. Không thay response
   bằng transcript tự tạo; report giải thích một attack source-to-sink cụ thể.

Chạy test public:

```bash
cd src
pytest ../tests/public -q
```

Public tests chỉ là regression. Auto-grader dùng hidden runtime probes có nonce
và biến thể nội dung nên không có artifact tĩnh nào thay thế được implementation.
