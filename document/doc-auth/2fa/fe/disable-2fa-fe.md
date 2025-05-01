# Giao Diện Người Dùng: Tắt Xác Thực 2 Yếu Tố (Disable 2FA)

**File:** `ui-disable-2fa.md`
**Ngày tạo:** 2025-04-30

---

## Mục Tiêu (Goal)

Cho phép người dùng đã đăng nhập và đã bật 2FA có thể tắt tính năng này sau khi xác minh danh tính bằng mã TOTP hoặc mã OTP gửi qua email.

---

## API Endpoint Liên Quan (Related API Endpoint)

1.  `POST /auth/disable-2fa` (Yêu cầu người dùng đã được xác thực)
2.  `POST /auth/send-otp` (với `type: TypeOfVerificationCode.DISABLE_2FA`, chỉ khi xác minh qua email)

---

## Luồng Logic Backend (Backend Logic Flow - Summary)

1.  **`disableTwoFactorAuth`**:
    * Lấy thông tin `user` dựa trên `userId` (từ token/session). Ném `EmailNotFoundException` nếu user không tồn tại.
    * Kiểm tra xem `user.totpSecret` có tồn tại không. Nếu **KHÔNG**, ném `TOTPNotEnabledException`.
    * Kiểm tra xem request có gửi kèm `totpCode` **HOẶC** `code` (OTP email) không. (Logic backend hiện tại yêu cầu ít nhất một trong hai phải có để thực hiện kiểm tra).
    * **Nếu CÓ `totpCode`:** Gọi `twoFactorService.verifyTOTP`. Ném `InvalidTOTPException` nếu mã không hợp lệ.
    * **Nếu CÓ `code` (và không có `totpCode`):** Gọi `validateVerificationCode` với `type = DISABLE_2FA`. Ném `InvalidOTPException` hoặc `OTPExpiredException` nếu không hợp lệ.
    * Nếu một trong hai phương thức xác minh trên thành công:
        * Cập nhật `user.totpSecret` thành `null` trong database.
        * Trả về thông báo thành công.

2.  **`sendOTP (DISABLE_2FA)`**: *(Chỉ được gọi khi UI cần gửi OTP cho bước xác minh)*
    * Tìm user bằng `email`.
    * Tạo mã `code` (OTP).
    * Lưu `email`, `code`, `type = DISABLE_2FA`, và `expiresAt`.
    * Gửi email chứa `code`. Ném `FailedToSendOTPException` nếu thất bại.
    * Trả về thông báo thành công.

---

## Các Thành Phần Giao Diện (UI Components)

*(Thường nằm trong trang Cài đặt Tài khoản / Bảo mật)*

* **Khu Vực Quản Lý 2FA (`<div class="two-factor-settings">`)**:
    * **Trạng Thái Hiện Tại (`<p>`)**: Hiển thị "Xác thực 2 yếu tố: **Đang bật**".
    * **Nút Tắt 2FA (`<button type="button" id="disable-2fa-btn">`)**:
        * Text: "Tắt Xác Thực 2 Yếu Tố"
        * *Hiển thị khi 2FA đang bật.*
* **Modal/Popup Xác Nhận Tắt 2FA (`<div id="disable-2fa-modal" style="display: none;">`)**: *Hiển thị sau khi nhấn "Tắt 2FA"*
    * **Tiêu đề**: "Xác nhận Tắt Xác thực 2 yếu tố"
    * **Hướng dẫn**: "Để tắt 2FA, vui lòng xác minh danh tính bằng một trong các cách sau:"
    * **Phương thức 1: TOTP**
        * TOTP Input (`<input type="text" name="totpCode">`)
            * Label: "Nhập mã từ ứng dụng Authenticator"
            * Placeholder: "Mã gồm 6 chữ số"
    * **Hoặc (Divider)**: "--- HOẶC ---"
    * **Phương thức 2: Email OTP**
        * Nút Gửi OTP Email (`<button type="button" id="send-disable-otp-btn">`)
            * Text: "Gửi mã xác thực qua Email"
            * *Trạng thái:* Disable khi đang gửi.
        * Vùng Thông Báo OTP (`<div class="disable-otp-feedback">`)
        * OTP Email Input (`<input type="text" name="code" disabled>`)
            * Label: "Mã Xác Thực (Email)"
            * Placeholder: "Nhập mã từ email"
            * *Trạng thái:* Enable sau khi gửi OTP thành công.
    * **Nút Xác Nhận Tắt (`<button type="button" id="confirm-disable-btn">`)**:
        * Text: "Xác Nhận Tắt 2FA"
        * *Trạng thái:* Disable khi đang xử lý.
    * **Nút Hủy (`<button type="button" id="cancel-disable-btn">`)**: Đóng modal.
    * **Vùng Thông Báo Lỗi Modal (`<div class="modal-feedback">`)**

---

## Luồng Tương Tác Người Dùng (User Interaction Workflow)

*(Giả định người dùng đã đăng nhập, 2FA đang bật và đang ở trang Cài đặt)*

1.  Giao diện hiển thị trạng thái 2FA là "Đang bật".
2.  Người dùng nhấn nút **"Tắt Xác Thực 2 Yếu Tố"**.
    * **Frontend:** Hiển thị **Modal Xác Nhận Tắt 2FA (`#disable-2fa-modal`)**.
3.  **Trong Modal:**
    * **Lựa chọn 1: Người dùng nhập mã TOTP**
        * Người dùng nhập mã vào **TOTP Input**.
        * Người dùng nhấn **"Xác Nhận Tắt 2FA"**.
            * **Frontend:** Disable nút "Xác Nhận Tắt". Hiển thị loading.
            * **Frontend Call API:** `POST /auth/disable-2fa` với `{ totpCode: totpCodeValue }` (Gửi kèm token xác thực).
            * **Xử lý Response:** (Xem Bước 4)
    * **Lựa chọn 2: Người dùng yêu cầu OTP qua Email**
        * Người dùng nhấn **"Gửi mã xác thực qua Email"**.
            * **Frontend:** Disable nút này. Hiển thị loading nhỏ.
            * **Frontend Call API:** `POST /auth/send-otp` với `{ email: userEmail, type: TypeOfVerificationCode.DISABLE_2FA }` (Lấy `userEmail` từ thông tin user đang đăng nhập, gửi kèm token xác thực).
            * **Xử lý Response:**
                * **Thành công (2xx):** Enable lại nút. Ẩn loading. Hiển thị thông báo trong `disable-otp-feedback` ("Đã gửi mã."). **Enable** trường **OTP Email Input**. Focus vào đó.
                * **Thất bại (4xx/5xx):** Enable lại nút. Ẩn loading. Hiển thị lỗi trong `disable-otp-feedback` ("Gửi mã thất bại.").
        * Người dùng nhập mã OTP nhận được vào **OTP Email Input**.
        * Người dùng nhấn **"Xác Nhận Tắt 2FA"**.
            * **Frontend:** Disable nút "Xác Nhận Tắt". Hiển thị loading.
            * **Frontend Call API:** `POST /auth/disable-2fa` với `{ code: otpCodeValue }` (Gửi kèm token xác thực).
            * **Xử lý Response:** (Xem Bước 4)

4.  **Xử lý Response của API `disable-2fa`:**
    * **Thành công (2xx):**
        * Ẩn loading.
        * **Đóng Modal**.
        * Cập nhật **Trạng Thái Hiện Tại** thành "Đang tắt".
        * Hiển thị nút "Bật Xác Thực 2 Yếu Tố".
        * Hiển thị thông báo thành công chung ("Đã tắt xác thực 2 yếu tố thành công!").
    * **Thất bại (4xx/5xx):**
        * Enable lại nút "Xác Nhận Tắt". Ẩn loading.
        * Hiển thị lỗi trong **Vùng Thông Báo Lỗi Modal (`modal-feedback`)**:
            * `TOTPNotEnabledException`: "Xác thực 2 yếu tố hiện chưa được bật." (Lỗi logic UI)
            * `InvalidTOTPException`: "Mã xác thực (TOTP) không hợp lệ."
            * `InvalidOTPException`: "Mã xác thực (Email OTP) không hợp lệ."
            * `OTPExpiredException`: "Mã xác thực (Email OTP) đã hết hạn."
            * Lỗi khác (401 Unauthorized, 500): "Không thể tắt 2FA vào lúc này."

---

## Xử Lý Trạng Thái & Phản Hồi (State Management & Feedback)

* Quản lý trạng thái hiển thị của Modal (`isDisableModalOpen`).
* Quản lý trạng thái loading cho các nút trong modal.
* Lưu trữ mã OTP hoặc TOTP người dùng nhập trong state của modal.
* Hiển thị/xóa thông báo lỗi trong modal.
* Cập nhật trạng thái 2FA chung (`is2FAEnabled`) sau khi thành công.

---

## Validation Phía Client (Client-Side Validation)

* Khi nhấn "Xác Nhận Tắt", kiểm tra xem người dùng đã nhập `totpCode` **HOẶC** `code` chưa.
* Kiểm tra định dạng mã (ví dụ: 6 chữ số).

---

## Lưu Ý Cho Intern (Notes for Intern)

* Chức năng này yêu cầu người dùng phải **đăng nhập** và **2FA đã bật**. Đảm bảo API call được gửi kèm token xác thực.
* Backend yêu cầu *ít nhất một* phương thức xác minh (`totpCode` hoặc `code`) để xử lý việc tắt 2FA. UI cần đảm bảo người dùng cung cấp một trong hai.
* Xử lý luồng gửi OTP qua email tương tự như các màn hình khác, nhưng với `type = DISABLE_2FA`.