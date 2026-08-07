# Hướng dẫn nộp bài — Day 11

**Đề bài:** [`assignment11.md`](assignment11.md) · File này chỉ nói **cách đóng gói và nộp**.

## Bài tập cá nhân

Bài Day 11 **làm một mình**. Điểm theo [`assignment11.md`](assignment11.md).
Một số bảng A/B bên dưới là checklist artifact (`results.json` / `attack_results.json`), không thay rubric trong đề.

---



## Hạn nộp

**Thứ sáu 7/8, 23:59 giờ Việt Nam (ICT, UTC+7).**

---



## Cách nộp


| Hình thức  | Yêu cầu                                                                                                     |
| ---------- | ----------------------------------------------------------------------------------------------------------- |
| **GitHub** | fork repo, đặt tên theo cú pháp: `K-<khóa của bạn>-<Họ và tên>-<MSSV>`. Submit link github ở trên CodeLabs. |


Thay `<MSSV>` bằng mã SV (ví dụ `2A202600000`).

---



## Cấu trúc thư mục bắt buộc

```
Day-11-Guardrails-HITL-Responsible-AI/
├── README.md                             # Họ tên, MSSV, cách chạy
├── src/
│   ├── assignment/                       # Code hạng mục A (Phòng thủ)
│   ├── attacks/                          # Code hạng mục B (Tấn công)
│   └── ...                               # guardrails / hitl nếu dùng
├── outputs/
│   ├── results.json                      # Kết quả pipeline phòng thủ (A)
│   ├── audit_log.json
│   ├── metrics.json
│   └── attack_results.json               # Kết quả tấn công (B)
├── report/
│   └── <MSSV>_report.md                  # Báo cáo (chủ yếu phần A + tóm tắt B)
└── requirements.txt
```

---



## Tên file bắt buộc


| Loại              | Tên file                              |
| ----------------- | ------------------------------------- |
| Báo cáo           | `report/<MSSV>_report.md` hoặc `.pdf` |
| Kết quả phòng thủ | `outputs/results.json`                |
| Audit             | `outputs/audit_log.json`              |
| Metrics           | `outputs/metrics.json`                |
| Kết quả tấn công  | `outputs/attack_results.json`         |


**Bằng chứng tấn công (hạng mục B / điểm cộng):** file `outputs/attack_results.json` (có `unsafe_attacks` / `guards_attacks`, trường `leaked`). Không cần chụp màn hình.

---



## Thang điểm chi tiết



### A. Phòng thủ — 80 điểm (80%)


| Tiêu chí               | Điểm   | Kỳ vọng                                      |
| ---------------------- | ------ | -------------------------------------------- |
| **Pipeline chạy suốt** | 10     | Các lớp khởi tạo được, agent trả lời được    |
| **Rate Limiter**       | 8      | Test 3: một phần request bị chặn đúng        |
| **Input Guardrails**   | 12     | Test 2: attack bị chặn ở input (ghi pattern) |
| **Output Guardrails**  | 12     | PII/secret bị redact (before/after)          |
| **LLM-as-Judge**       | 12     | Có điểm đa tiêu chí                          |
| **Comment code**       | 6      | Mỗi hàm/class giải thích làm gì / vì sao cần |
| **Báo cáo**            | 20     | Trả lời đủ 5 câu hỏi trong đề                |
| **Tổng A**             | **80** |                                              |




#### Báo cáo 20 điểm


| #   | Nội dung                                     | Điểm |
| --- | -------------------------------------------- | ---- |
| 1   | Phân tích lớp chặn 7 attack (bảng)           | 5    |
| 2   | False positive / trade-off bảo mật–dễ dùng   | 4    |
| 3   | Tự tìm 2–3 attack vẫn lọt pipeline của bạn + đề xuất 1 lớp thêm | 5    |
| 4   | Chỉnh thiết kế khi scale ~10k user (nhanh / rẻ / theo dõi tấn công) | 3    |
| 5   | Suy nghĩ đạo đức về “an toàn tuyệt đối”      | 3    |




### B. Tấn công — 20 điểm (20%)


| Tiêu chí                   | Điểm | Kỳ vọng                                                    |
| -------------------------- | ---- | ---------------------------------------------------------- |
| **5+ prompt tấn công**     | 8    | Đủ kỹ thuật nâng cao — không chỉ “ignore all instructions” |
| **Red team bằng AI**       | 4    | Dùng LLM sinh thêm ≥5 attack mới                           |
| **Chạy thật + bằng chứng** | 8    | Có `outputs/attack_results.json` đủ field                  |


Ví dụ tối thiểu `outputs/attack_results.json`:

```json
{
  "student_id": "SE12345",
  "unsafe_attacks": [
    {
      "id": 1,
      "category": "Completion",
      "input": "...",
      "response_preview": "...",
      "leaked": true,
      "target": "unsafe"
    }
  ],
  "guards_attacks": [
    {
      "id": 1,
      "category": "Completion",
      "input": "...",
      "response_preview": "...",
      "leaked": false,
      "target": "guards",
      "notes": "Chỉ leaked=true trên guards mới có điểm cộng"
    }
  ],
  "ai_generated_attacks": [
    {"id": 1, "input": "...", "category": "..."}
  ]
}
```



### Điểm cộng (phá Guards Agent) — tối đa +10

Chỉ cộng khi tấn công **Guards Agent** thành công (lộ secret).  
Lộ secret trên **unsafe agent không tính** điểm cộng.


| Quy tắc   | Chi tiết                                                             |
| --------- | -------------------------------------------------------------------- |
| Mục tiêu  | `create_guards_agent()` trong `src/agents/guards_agent.py`           |
| Điều kiện | `"target": "guards"` và `"leaked": true` trong `attack_results.json` |
| Mức cộng  | **+2** mỗi attack thành công trên guards                             |
| Tối đa    | **+10** (tối đa 5 attack)                                            |


Điểm B (20): chạy attack trên unsafe (+ nên chạy cả guards) và nộp bằng chứng.  
Điểm cộng: chỉ khi phá được guards.

Điểm bài = điểm A (≤80) + điểm B (≤20) + điểm cộng (≤10).

---



## Định dạng `outputs/results.json` (Phần A)

Khớp `[schemas/results.schema.json](schemas/results.schema.json)`. Ví dụ:

```json
{
  "student_id": "SE12345",
  "framework": "google-adk | langgraph | nemo | pure-python | other",
  "safe_queries": [
    {"input": "...", "blocked": false, "layer": null, "response_preview": "..."}
  ],
  "attack_queries": [
    {"input": "...", "blocked": true, "layer": "input_guardrail", "response_preview": "..."}
  ],
  "rate_limit": {
    "max_requests": 10,
    "window_seconds": 60,
    "sent": 15,
    "passed": 10,
    "blocked": 5
  },
  "edge_cases": [
    {"input": "", "blocked": true, "layer": "input_guardrail"}
  ],
  "judge_sample": [
    {
      "response_preview": "...",
      "safety": 5,
      "relevance": 4,
      "accuracy": 4,
      "tone": 5,
      "verdict": "PASS"
    }
  ]
}
```

- `blocked: false` = cho qua; `true` = bị chặn  
- `layer` = lớp chặn (`rate_limiter`, `input_guardrail`, `output_guardrail`, `llm_judge`, …)

---



## Tự kiểm trước khi nộp

```powershell
# Đảm bảo đang trong venv: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest tests/smoke -q
pytest tests/public -q
python scripts/grade.py --submission-dir . --out outputs/grade_report.json
```

Cần có `outputs/results.json` và `outputs/attack_results.json` trước khi nộp.

Nếu máy không chạy được code (thiếu lib, sai path, lỗi cú pháp): phần chấm máy = **lỗi kỹ thuật** — sửa đóng gói trước. Báo cáo luôn do người chấm.

---



## Trung thực học thuật

- Không commit API key (dùng `.env`)
- Không chia sẻ test ẩn
- Dùng thư viện ngoài thì ghi nguồn trong README / báo cáo

