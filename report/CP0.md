# Báo Cáo Checkpoint 0 — Cài Đặt Môi Trường & Chạy Thử (Baseline Setup)

**Học viên:** Nguyễn Đức Nam Khánh  
**MSSV:** 2A202601103  
**Lớp / Cohort:** K3  
**Hệ thống:** VinBank AI Assistant (Controlled Security Guardrails)  

---

## 1. Tổng Quan Mục Tiêu Checkpoint 0

Checkpoint 0 tập trung vào việc khởi tạo môi trường phát triển, chuẩn hóa cấu trúc repository cá nhân cho lớp K3, cài đặt các phụ thuộc bắt buộc (Python dependencies) và kiểm tra khả năng chạy test ban đầu (smoke tests & public contracts).

Mục tiêu chính:
- Clone repo cá nhân `K3-Day11-2A202601103-NguyenDucNamKhanh`.
- Khởi tạo môi trường ảo Python và cài đặt các thư viện lõi: `google-adk`, `google-genai`, `pytest`, `nemoguardrails`, `pandas`, `pydantic`.
- Thực thi các lệnh smoke test và public contract test để xác nhận baseline khởi tạo.

---

## 2. Các Bước Thực Hiện Môi Trường

### 2.1 Cài Đặt Phụ Thuộc (Requirements)
Lệnh thực thi trong terminal:
```powershell
python -m pip install -U pip
pip install -r requirements.txt
```

Các thư viện chính được ghi nhận trong môi trường:
- `google-adk`: Thư viện Agent Development Kit của Google (quản lý Runner, Plugin architecture, InvocationContext).
- `google-genai`: SDK kết nối Gemini API models (Gemini 2.0 Flash, Gemini 2.5 Flash).
- `pytest`: Framework chạy kiểm thử tự động.

### 2.2 Cấu Hình API Key & Environment Variable
Cập nhật file `src/core/config.py` hỗ trợ cả hai chế độ (Dev offline / Mock key và Production Google AI Studio API Key):
```python
def setup_api_key():
    """Load Google API key from environment or default."""
    if "GOOGLE_API_KEY" not in os.environ or not os.environ["GOOGLE_API_KEY"].strip():
        os.environ["GOOGLE_API_KEY"] = "MOCK_API_KEY_LAB11"
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
```
Thiết lập `STUDENT_ID="2A202601103"` xuyên suốt các pipeline phòng thủ và báo cáo.

---

## 3. Kết Quả Kiểm Thử Ban Đầu (Smoke & Contract Baseline)

Lệnh chạy kiểm thử:
```powershell
pytest tests/smoke -q
pytest tests/public -q
```

### Kết Quả Baseline:
1. **Smoke Tests (`tests/smoke`)**: `PASS` (5/5 tests passed). Xác nhận cấu trúc module `src/guardrails`, `src/assignment`, `src/hitl`, `src/attacks`, `src/agents` đầy đủ.
2. **Public Tests (`tests/public`)**: Fail ban đầu do starter chứa các hàm TODO (`NotImplementedError` hoặc chưa có logic chặn). Đây là trạng thái hợp lệ chứng minh test runner đang hoạt động chính xác.

---

## 4. Đánh Giá Trạng Thái Checkpoint 0

- [x] Repo fork thành công và mở đúng workspace `K3-Day11-2A202601103-NguyenDucNamKhanh`.
- [x] Môi trường Python 3.10+ cài đủ tất cả gói phụ thuộc trong `requirements.txt`.
- [x] Khởi chạy thành công suite test `pytest tests/smoke` và sẵn sàng bước sang Checkpoint 1.
