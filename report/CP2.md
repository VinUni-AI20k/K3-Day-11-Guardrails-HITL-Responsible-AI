# Báo Cáo Checkpoint 2 — Không Để Lộ Dữ Liệu Hoặc Tự Làm Action Nguy Hiểm (Output Guardrails & Egress Policy)

**Học viên:** Nguyễn Đức Nam Khánh  
**MSSV:** 2A202601103  
**Lớp / Cohort:** K3  
**Hệ thống:** VinBank AI Assistant (Controlled Security Guardrails)  

---

## 1. Mục Tiêu Checkpoint 2

Checkpoint 2 tập trung vào 2 phòng tuyến quan trọng ở phía đầu ra và cổng giao tiếp ngoại vi (Egress Gateway):
1. **Output Guardrails (`src/guardrails/output_guardrails.py`)**: Lọc bỏ các thông tin nhạy cảm (PII: Số điện thoại, Email, Số CMND/CCCD) và các bí mật hệ thống (Admin Passwords, API Keys, Database Connection String) trước khi phản hồi gửi về cho người dùng.
2. **LLM-as-a-Judge**: Khởi tạo một LLM Judge (`safety_judge`) độc lập đánh giá phản hồi cuối cùng của Agent trước khi phát ra.
3. **Egress Policy Gateway (`is_egress_allowed`)**: Ngăn chặn tuyệt đối việc agent tự động đẩy dữ liệu nhạy cảm ra các domain giả mạo hoặc endpoint chưa được duyệt trong Allowlist.

---

## 2. Thiết Kế Implementation

### 2.1 Content Filter & PII Redaction (`content_filter`)
Áp dụng Regex pattern lọc và che dấu dữ liệu nhạy cảm bằng nhãn `[REDACTED]`:
- **Password**: `admin123`, `password\s*[:=]\s*\S+`
- **API Key**: `sk-[a-zA-Z0-9-]+`
- **Database Host**: `db\.vinbank\.internal`
- **Phone Number (VN)**: `0\d{9,10}`
- **Email**: `[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}`
- **National ID**: `\b\d{9}\b|\b\d{12}\b`

### 2.2 Egress Hostname Allowlist (`is_egress_allowed` trong `src/assignment/pipeline.py`)
Nguyên tắc cốt lõi: **Không phụ thuộc vào phán đoán văn bản của LLM**. Hàm `is_egress_allowed` thực hiện:
1. Parse URL bằng `urllib.parse.urlparse`.
2. Yêu cầu protocol phải là `https`.
3. Hostname phải **khớp chính xác 100%** với endpoint ngân hàng cho phép: `api.vinbank.example`. (Domain giả dạng `api.vinbank.example.evil.com` hoặc `evil.example` lập tức bị **BLOCK**).
4. Kiểm tra payload string không chứa password, API key, DB host, phone, email.

```python
def is_egress_allowed(destination: str, payload: str | dict) -> bool:
    if not destination or not isinstance(destination, str):
        return False
    parsed = urlparse(destination)
    if parsed.scheme.lower() != "https" or parsed.hostname != "api.vinbank.example":
        return False
    payload_str = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, payload_str, re.IGNORECASE):
            return False
    return True
```

---

## 3. Thử Nghiệm & Kết Quả (Verification Matrix)

| Domain/Destination Target | Payload Nội Dung | Kết quả Egress | Lý do an toàn |
| :--- | :--- | :--- | :--- |
| `https://api.vinbank.example/v1/transfers` | `{"account": "123", "amount": 500000}` | **ALLOW** | Đúng HTTPS host & Payload hợp lệ |
| `https://api.vinbank.example.evil.com/transfers` | `{"account": "123", "amount": 500000}` | **BLOCK** | Hostname giả mạo (Subdomain attack) |
| `https://evil.example/collect` | `{"account": "123"}` | **BLOCK** | Hostname ngoài Allowlist |
| `https://api.vinbank.example/v1/transfers` | `{"note": "admin123"}` | **BLOCK** | Payload chứa secret (Admin Password) |
| `https://api.vinbank.example/v1/transfers` | `{"email": "test@vinbank.com"}` | **BLOCK** | Payload chứa PII Email |

### Kết Quả Pytest Contract:
```powershell
pytest tests/public/test_lab_contracts.py -k "content_filter or egress"
# PASSED: test_content_filter_redacts_secrets
# PASSED: test_egress_policy_blocks_sensitive_payload_and_unknown_destination
```

---

## 4. Kết Luận Checkpoint 2

- [x] Lọc triệt để secret (`admin123`, `sk-vinbank-secret-2024`, `db.vinbank.internal`) và PII khỏi response output.
- [x] Triển khai Egress Policy kiểm soát chặt chẽ điểm đến (Destination) và dữ liệu đi ra (Payload).
- [x] Ngăn chặn các đòn tấn công Typosquatting / Fake Subdomain (`api.vinbank.example.evil.com`).
- [x] Pass 100% public test contracts về Output & Egress Safety.
