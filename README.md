# Day 11 — Guardrails, HITL & Responsible AI

**Họ tên:** Nguyễn Việt Linh  
**MSSV:** 2A202601211  

Làm sao để ứng dụng agent an toàn hơn?

**Hình thức:** bài tập **cá nhân** (1 người / 1 MSSV).

---

## Hai hạng mục cần làm

| Hạng mục | Tỷ lệ | Bạn làm gì |
|----------|-------|------------|
| **A. Phòng thủ** | **80%** | Xây pipeline bảo vệ nhiều lớp + báo cáo |
| **B. Tấn công** | **20%** | Viết prompt tấn công agent, red team bằng AI, ghi nhận kết quả |
| **Điểm cộng** | tối đa **+10** | Chỉ khi **phá được Guards Agent** (lộ secret) — xem đề bài |

**Gợi ý:** làm **Phòng thủ (A)** trước, **Tấn công (B)** sau.

**Hạn nộp:** Thứ sáu **7/8**, **23:59 giờ Việt Nam (ICT)**.

| Tài liệu | Dùng để |
|----------|---------|
| [`assignment11_defense_pipeline.md`](assignment11_defense_pipeline.md) | Đề bài chi tiết (A + B) |
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

### Hạng mục A — Phòng thủ (làm trước)

1. Code trong `src/assignment/` (dùng lại `src/guardrails/`, `src/hitl/`)
2. Chạy Test 1–4 → `outputs/results.json`, `audit_log.json`, `metrics.json`
3. Báo cáo: `report/2A202601211_report.md`
4. Chi tiết: đề bài mục **Hạng mục A — Phòng thủ**

```powershell
$env:PYTHONPATH = "src"
python -m assignment.pipeline
# hoặc: cd src; python main.py --part 5

python -m pytest tests/smoke -q
python -m pytest tests/public -q
python scripts/grade.py --submission-dir . --out outputs/grade_report.json
```

### Hạng mục B — Tấn công (làm sau)

1. Prompt trong `src/attacks/attacks.py` (≥5 kỹ thuật)
2. Chạy (tấn công **unsafe** rồi **guards**):

```powershell
cd src
python main.py --part 1
```

3. Unsafe = hạng mục B · Guards (`src/agents/guards_agent.py`) = **điểm cộng nếu LEAKED**  
4. Lưu `outputs/attack_results.json` (có cả `unsafe_attacks` và `guards_attacks`)

Nộp theo [`SUBMISSION.md`](SUBMISSION.md).

---

## Cấu trúc repo

```
├── assignment11_defense_pipeline.md   ← Đề bài A + B
├── SUBMISSION.md                      ← Quy định nộp
├── src/
│   ├── assignment/                    ← Hạng mục A (Phòng thủ)
│   ├── attacks/                       ← Hạng mục B (Tấn công)
│   ├── agents/guards_agent.py         ← Guards Agent (mục tiêu điểm cộng)
│   ├── guardrails/ testing/ hitl/     ← Module hỗ trợ phòng thủ
│   └── main.py
├── report/2A202601211_report.md
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
