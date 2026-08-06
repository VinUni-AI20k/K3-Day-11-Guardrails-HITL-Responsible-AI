# Day 11 — Controlled Agent Security (2026)

Làm sao để ứng dụng agent an toàn hơn?

> **Dùng assignment mới:** đọc [assignment11_agent_security_2026.md](assignment11_agent_security_2026.md).
> Tài liệu pipeline cũ được giữ làm tham khảo API/starter, nhưng rubric 2026 chấm
> theo untrusted content, quyền action, HITL, egress và incident response.

**Hình thức:** bài tập **cá nhân** (1 người / 1 MSSV).

---

## Rubric 2026

| Năng lực | Điểm | Bạn làm gì |
|---|---:|---|
| Direct + indirect guardrails | 35 | Xử lý jailbreak, email/RAG untrusted, Unicode và false positive |
| Permission + HITL | 35 | Egress allowlist, high-risk action, approval/reject/timeout/audit |
| Output + incident response | 20 | Redact PII/secret, monitoring, correlation trace |
| Red team | 10 | Attack taxonomy và report source-to-sink |
| Bonus | +10 | Verifier replay xác nhận Guards leak; không tin transcript tự khai |

**Gợi ý:** làm **Phòng thủ (A)** trước, **Tấn công (B)** sau.

**Hạn nộp:** Thứ sáu **7/8**, **23:59 giờ Việt Nam (ICT)**.

| Tài liệu | Dùng để |
|----------|---------|
| [`assignment11_agent_security_2026.md`](assignment11_agent_security_2026.md) | Đề bài và rubric hiện hành |
| [`assignment11_defense_pipeline.md`](assignment11_defense_pipeline.md) | Walkthrough starter cũ (tham khảo) |
| [`SUBMISSION.md`](SUBMISSION.md) | Cách nộp, tên file, cấu trúc thư mục |

---

## Tình huống

Chatbot ngân hàng **VinBank**. Agent “unsafe” cố ý chứa mật khẩu / API key trong system prompt.

```
Câu hỏi người dùng
    → Rate Limiter
    → Lọc đầu vào (Input Guardrails)
    → LLM trả lời
    → Lọc đầu ra (Output Guardrails + Judge)
    → Audit / Monitoring
    → Phản hồi
```

---

## Làm bài trên máy

### Cài đặt

```powershell
Copy-Item .env.example .env
# Mở .env, dán GOOGLE_API_KEY
pip install -r requirements.txt
```

Lấy key: [Google AI Studio](https://aistudio.google.com/apikey)

### Phần bắt buộc — Controlled Agent Security

1. Code trong `src/assignment/` (có thể dùng lại `src/guardrails/`, `src/hitl/`)
2. Implement `is_egress_allowed`, indirect-content guard, HITL lifecycle, audit và monitoring
3. Viết `report/<MSSV>_report.md`
4. Chi tiết: [`assignment11_agent_security_2026.md`](assignment11_agent_security_2026.md)

```powershell
pytest tests/smoke -q
pytest tests/public -q
python scripts/grade.py --submission-dir . --out outputs/grade_report.json
```

### Red team và bonus

1. Viết ≥5 prompt vào `src/attacks/attacks.py`
2. Chạy local (tấn công **unsafe demo** rồi **public Guards reference**):

```powershell
cd src
python main.py --part 1
```

3. Unsafe là target minh hoạ có dữ liệu giả. Guards (`src/agents/guards_agent.py`) là policy reference công khai, không chứa secret và không phải bonus target.
4. Nộp tối đa 5 prompt attack. Host verifier mới replay prompt đó lên target riêng với fresh canary để quyết định bonus; local transcript chỉ là evidence học tập.

Colab / Jupyter (tuỳ chọn): `notebooks/lab11_guardrails_hitl.ipynb`. Local là đủ.

Nộp theo [`SUBMISSION.md`](SUBMISSION.md).

---

## Cấu trúc repo

```
├── assignment11_agent_security_2026.md ← Đề bài 2026
├── assignment11_defense_pipeline.md   ← Walkthrough cũ (tham khảo)
├── SUBMISSION.md                      ← Quy định nộp
├── data/pii_hallucination_samples.json ← PII + ground_truth đối chiếu hallucination
├── src/
│   ├── assignment/                    ← Hạng mục A (Phòng thủ) — starters
│   ├── attacks/                       ← Hạng mục B (Tấn công)
│   ├── agents/security_boundary.py    ← Reference provenance / action boundary
│   ├── agents/guards_agent.py         ← Public Guards policy reference (không có secret)
│   ├── guardrails/ testing/ hitl/     ← Module hỗ trợ phòng thủ
│   └── main.py
├── notebooks/lab11_guardrails_hitl.ipynb
├── schemas/results.schema.json
├── scripts/grade.py
├── tests/
├── Slide_Lab_Day11.html
└── .env.example
```

---

## Tài liệu tham khảo

- [OWASP Top 10 for LLM](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)
- [Google ADK](https://google.github.io/adk-docs/)
- [AI Safety Fundamentals](https://aisafetyfundamentals.com/)
