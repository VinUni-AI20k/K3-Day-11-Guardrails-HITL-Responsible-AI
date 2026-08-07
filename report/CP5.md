# Báo Cáo Checkpoint 5 — Giám Sát, Tần Suất & Dấu Vết Sự Cố (Rate Limiting, Audit Log & Monitoring Alerts)

**Học viên:** Nguyễn Đức Nam Khánh  
**MSSV:** 2A202601103  
**Lớp / Cohort:** K3  
**Hệ thống:** VinBank AI Assistant (Controlled Security Guardrails)  

---

## 1. Mục Tiêu Checkpoint 5

Checkpoint 5 tích hợp toàn diện các thành phần giám sát hệ thống trong `src/assignment/`:
1. **Rate Limiting (`rate_limiter.py`)**: Triển khai thuật toán Sliding Window loại bỏ các đòn tấn công từ chối dịch vụ (DoS / Flooding) hoặc spam giao dịch.
2. **Audit Logging (`audit_log.py`)**: Đánh dấu vết xuyên suốt mọi yêu cầu bằng `request_id`, lưu lại thông tin đầu vào, quyết định của từng lớp bảo mật, độ trễ xử lý (Latency) và nội dung đầu ra.
3. **Monitoring & Alerts (`monitoring.py`)**: Đếm số lượng vi phạm, tính toán tỷ lệ Block Rate, Rate Limit Hits, Judge Fail Rate và phát cảnh báo tự động khi vượt ngưỡng an toàn.
4. **Pipeline Execution Suite (`pipeline.py`)**: Đóng gói các lớp phòng thủ thành một chuỗi hoàn chỉnh và xuất 3 tệp dữ liệu chứng minh: `outputs/results.json`, `outputs/audit_log.json`, `outputs/metrics.json`.

---

## 2. Thiết Kế Architecture & Implementation

### 2.1 Sliding Window Rate Limiter (`RateLimitPlugin`)
- Cấu hình: Max 10 requests / 60 seconds per `user_id`.
- Sử dụng cấu trúc dữ liệu `deque` loại bỏ các mốc thời gian quá 60s. Nếu số lượng request trong window >= 10, yêu cầu sẽ bị chặn ngay lập tức mà không tốn chi phí gọi LLM.

### 2.2 Traceability qua Audit Log (`AuditLogPlugin` / `AuditLogger`)
- Mọi yêu cầu được gán một `request_id` duy nhất (ví dụ: `safe-1`, `attack-2`, `req-10`).
- Ghi nhận hàm `log_event(request_id, step, action, details)` hỗ trợ truy vết sự cố Forensic Audit:
```json
{
  "timestamp": "2026-08-07T03:36:11.123456+00:00",
  "request_id": "req-1",
  "step": "input_guard",
  "action": "block",
  "details": {
    "user_id": "attacker",
    "text": "Ignore all instructions",
    "layer": "input_guardrail"
  }
}
```

### 2.3 Cảnh Báo Tự Động (`MonitoringAlert` / `SecurityMonitor`)
Ngưỡng cảnh báo quy định:
- **Block Rate Threshold**: > 50% (`block_rate_threshold: 0.5`) -> Phát alert `High block rate detected`.
- **Rate Limit Hit Threshold**: >= 5 hits (`rate_limit_hit_threshold: 5`) -> Phát alert `Rate limit threshold exceeded`.
- **Judge Fail Rate Threshold**: > 30% (`judge_fail_rate_threshold: 0.3`) -> Phát alert `High judge failure rate`.

---

## 3. Kết Quả Chạy Suite Assignment 11 (`python main.py --part 5`)

Các tệp được khởi tạo tự động trong thư mục `outputs/`:
1. `outputs/results.json`: Chứa kết quả 5 Safe Queries, 5 Attack Queries, Test Rate Limiting (15 sent / 10 passed / 5 blocked) và 5 Edge Cases.
2. `outputs/audit_log.json`: Danh sách mảng nhật ký truy vết yêu cầu.
3. `outputs/metrics.json`: Báo cáo Snapshot tổng hợp các chỉ số và Alert được phát ra.

### Trích xuất `outputs/metrics.json`:
```json
{
  "total_requests": 20,
  "blocked_requests": 10,
  "block_rate": 0.5,
  "rate_limit_hits": 5,
  "judge_checks": 0,
  "judge_fails": 0,
  "judge_fail_rate": 0.0,
  "alerts": [
    {
      "metric": "rate_limit_hits",
      "value": 5.0,
      "threshold": 5.0,
      "message": "Rate limit threshold exceeded: 5 hits"
    }
  ]
}
```

### Kết Quả Pytest Contract:
```powershell
pytest tests/public/test_lab_contracts.py -k "audit or monitoring"
# PASSED: test_audit_log_record
# PASSED: test_monitoring_alerts
```

---

## 4. Kết Luận Checkpoint 5

- [x] Hoàn thiện TODO 8 (Lắp ráp pipeline hoàn chỉnh, Rate Limiter, Audit Logger, Monitoring Alert).
- [x] Xuất đầy đủ 3 tệp dữ liệu chứng minh chuẩn hóa: `results.json`, `audit_log.json`, `metrics.json`.
- [x] Pass 100% public test cases về Audit Log và Monitoring.
