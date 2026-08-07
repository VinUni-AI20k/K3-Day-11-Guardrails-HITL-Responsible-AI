# Báo Cáo Checkpoint 4 — Thiết Kế Người Duyệt & Duy trì Quy Trình (HITL & Confidence Router)

**Học viên:** Nguyễn Đức Nam Khánh  
**MSSV:** 2A202601103  
**Lớp / Cohort:** K3  
**Hệ thống:** VinBank AI Assistant (Controlled Security Guardrails)  

---

## 1. Mục Tiêu Checkpoint 4

Checkpoint 4 triển khai cơ chế kiểm soát con người (**Human-in-the-Loop - HITL**) tại `src/hitl/hitl.py` nhằm:
1. Định tuyến phản hồi tự động dựa trên điểm tin cậy (**Confidence Score**) thông qua `ConfidenceRouter`.
2. Đưa các tác vụ rủi ro cao (**HIGH_RISK_ACTIONS**) bắt buộc qua con người xét duyệt, không cho phép AI tự động đưa ra quyết định hành động tác động tới tài khoản/tiền tệ.
3. Thiết kế chi tiết 3 điểm quyết định HITL (HITL Decision Points) bao gồm ngữ cảnh hiển thị, luồng duyệt approve/reject/timeout và trường log kiểm toán (Audit Trail).

---

## 2. Thiết Kế Implementation (`src/hitl/hitl.py`)

### 2.1 Ma Trận Định Tuyến Tin Cậy (`ConfidenceRouter`)
- **Tác vụ Rủi ro Cao (`HIGH_RISK_ACTIONS`)**: `transfer_money`, `close_account`, `change_password`, `delete_data`, `update_personal_info` -> **Luôn luôn `escalate`** (Bắt buộc con người phê duyệt, priority `high`).
- **Tác vụ Thông thường**:
  - `confidence >= 0.90`: `auto_send` (Gửi tự động, priority `low`).
  - `0.70 <= confidence < 0.90`: `queue_review` (Đưa vào hàng đợi duyệt, priority `normal`).
  - `confidence < 0.70`: `escalate` (Leo thang khẩn cấp tới chuyên viên, priority `high`).

### 2.2 Ba Điểm Quyết Định HITL (HITL Decision Points)

#### Decision Point #1: Phê Duyệt Giao Dịch Chuyển Tiền Giá Trị Lớn
- **Trigger**: Yêu cầu hành động `transfer_money` hoặc số tiền giao dịch > 10.000.000 VNĐ.
- **HITL Model**: `human-in-the-loop`
- **Context Hiển thị cho Reviewer**: Tài khoản gửi, Tên/Số tài khoản/Ngân hàng nhận, Số tiền chuyển, Trạng thái xác thực OTP/Biometric session của khách hàng, Điểm số cảnh báo rủi ro (Risk Flag Score).
- **Quy trình Phê duyệt**:
  - **Approve**: Đẩy lệnh giao dịch sang Egress API `api.vinbank.example/v1/transfers`.
  - **Reject**: Hủy giao dịch và gửi thông báo lý do cho khách hàng.
  - **Timeout (5 phút)**: Tự động hủy lệnh để bảo đảm an toàn tài chính.
- **Audit Fields**: `request_id`, `correlation_id`, `user_id`, `action_type`, `proposed_diff`, `reviewer_id`, `reviewer_decision`, `timestamp`.

#### Decision Point #2: Thay Đổi Thông Tin Cá Nhân / Đóng Tài Khoản
- **Trigger**: Yêu cầu `close_account`, `change_password` hoặc `update_personal_info`.
- **HITL Model**: `human-in-the-loop`
- **Context Hiển thị cho Reviewer**: ID tài khoản, Diff thông tin thay đổi (Cũ vs Mới), Lịch sử xác minh khách hàng, Trạng thái dư nợ/kê biên.
- **Quy trình Phê duyệt**:
  - **Approve**: Ghi nhận thay đổi vào DB lõi ngân hàng.
  - **Reject**: Từ chối và ghi log cảnh báo bảo mật.
  - **Timeout**: Chuyển tiếp tới hàng đợi kiểm tra nâng cao của Trưởng nhóm CSKH.
- **Audit Fields**: `request_id`, `correlation_id`, `user_id`, `action_type`, `proposed_diff`, `reviewer_id`, `decision_notes`, `timestamp`.

#### Decision Point #3: Leo Thang Cảnh Báo Gian Lận / Độ Tin Cậy Thấp
- **Trigger**: Confidence score < 0.70 hoặc hệ thống Anomaly Detection gắn cờ nghi vấn gian lận.
- **HITL Model**: `human-as-tiebreaker`
- **Context Hiển thị cho Reviewer**: Query gốc của người dùng, Văn bản RAG trích xuất, Danh sách phản hồi ứng viên của AI kèm điểm số tin cậy.
- **Quy trình Phê duyệt**:
  - **Approve**: Chọn 1 phản hồi an toàn gửi cho người dùng.
  - **Override**: Chuyên viên tự soạn câu trả lời chuẩn nghiệp vụ.
  - **Timeout**: Trả về câu xin lỗi và hẹn phản hồi sau.
- **Audit Fields**: `request_id`, `correlation_id`, `user_id`, `confidence_score`, `candidate_responses`, `reviewer_id`, `final_response`, `timestamp`.

---

## 3. Thử Nghiệm Định Tuyến (Verification Log)

```
================================================================================
Scenario                  Conf   Action Type        Decision        Priority   Human?
--------------------------------------------------------------------------------
Balance inquiry           0.95   general            auto_send       low        No
Interest rate question    0.82   general            queue_review    normal     Yes
Ambiguous request         0.55   general            escalate        high       Yes
Transfer $50,000          0.98   transfer_money     escalate        high       Yes
Close my account          0.91   close_account      escalate        high       Yes
================================================================================
```

### Kết Quả Pytest Contract:
```powershell
pytest tests/public/test_lab_contracts.py -k "router or hitl"
# PASSED: test_confidence_router_high_risk_always_escalates
# PASSED: test_confidence_router_thresholds
# PASSED: test_hitl_points_include_reviewer_lifecycle
```

---

## 4. Kết Luận Checkpoint 4

- [x] Hoàn thiện TODO 11 (Confidence Router chặn đứng các hành động rủi ro cao).
- [x] Hoàn thiện TODO 12 (Thiết kế chi tiết 3 HITL decision points cùng vòng đời Approve/Reject/Timeout).
- [x] Pass 100% public test cases về Router và HITL Decision Points.
