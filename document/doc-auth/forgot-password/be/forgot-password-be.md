# Giao Diện Người Dùng: Quên Mật Khẩu (Forgot Password)

**File:** `ui-forgot-password.md`
**Ngày tạo:** 2025-04-30

---

## Mục Tiêu (Goal)

Cho phép người dùng đặt lại mật khẩu nếu họ quên mật khẩu hiện tại, bằng cách xác thực qua email OTP.

--- 

## API Endpoint Liên Quan (Related API Endpoint)

1.  `POST /auth/send-otp` (với `type: TypeOfVerificationCode.FORGOT_PASSWORD`)
2.  `POST /auth/forgot-password`

---

## Luồng Logic Backend (Backend Logic Flow - Summary)

1.  **`sendOTP (FORGOT_PASSWORD)`**:
    * Kiểm tra xem `email` có tồn tại trong `SharedUserRepository` không.
    * Nếu **KHÔNG tồn tại**, ném lỗi `EmailNotFoundException`.
    * Nếu **CÓ tồn tại**:
        * Tạo mã `code` (OTP).
        * Lưu `email`, `code`, `type = FORGOT_PASSWORD`, và `expiresAt`.
        * Gửi email chứa `code`. Ném `FailedToSendOTPException` nếu gửi thất bại.
        * Trả về thông báo thành công.
2.  **`forgotPassword`**:
    * Tìm user bằng `email`. Ném `EmailNotFoundException` nếu không tìm thấy (kiểm tra lại).
    * Gọi `validateVerificationCode` để kiểm tra `email`, `code`, và `type = FORGOT_PASSWORD`.
        * Ném `InvalidOTPException` nếu không tìm thấy bản ghi phù hợp.
        * Ném `OTPExpiredException` nếu mã đã hết hạn.
    * Hash mật khẩu mới (`newPassword`).
    * Cập nhật `password` cho user.
    * Xóa bản ghi Verification Code đã sử dụng.
    * Trả về thông báo thành công.

---

## Luồng Tương Tác Người Dùng (User Interaction Workflow)

1.  **Giai đoạn 1: Yêu cầu Mã Reset**
    * Người dùng nhập **Email**.
    * Frontend thực hiện **Client-Side Validation** (định dạng email).
    * Người dùng nhấn **"Gửi Mã Đặt Lại Mật Khẩu"**.
        * **Frontend:** Lưu lại email đã nhập. Disable nút. Hiển thị loading.
        * **Frontend Call API:** `POST /auth/send-otp` với `{ email: emailValue, type: TypeOfVerificationCode.FORGOT_PASSWORD }`.
        * **Xử lý Response:**
            * **Thành công (2xx):**
                * Ẩn loading.
                * **Ẩn Giai đoạn 1**.
                * **Hiển thị Giai đoạn 2**. Hiển thị email đã nhập. Focus vào trường **OTP Input**.
                * Hiển thị thông báo hướng dẫn trong `feedback-step2` ("Vui lòng kiểm tra email để lấy mã OTP.").
            * **Thất bại (4xx/5xx):**
                * Enable lại nút. Ẩn loading.
                * Hiển thị lỗi trong `feedback-step1`:
                    * `EmailNotFoundException`: "Không tìm thấy tài khoản nào với email này."
                    * `FailedToSendOTPException`: "Không thể gửi mã vào lúc này. Vui lòng thử lại."
                    * Lỗi khác: "Đã có lỗi xảy ra."

2.  **Giai đoạn 2: Đặt Lại Mật Khẩu**
    * Người dùng nhập **Mã Xác Nhận OTP**, **Mật Khẩu Mới**, và **Xác Nhận Mật Khẩu Mới**.
    * Frontend thực hiện **Client-Side Validation** (required, mật khẩu khớp).
    * Người dùng nhấn **"Đặt Lại Mật Khẩu"**.
        * **Frontend:** Disable nút. Hiển thị loading.
        * **Frontend Call API:** `POST /auth/forgot-password` với `{ email: savedEmail, code: otpValue, newPassword: newPasswordValue }`.
        * **Xử lý Response:**
            * **Thành công (2xx):**
                * Ẩn loading.
                * Hiển thị thông báo thành công trong `feedback-step2` ("Đặt lại mật khẩu thành công!").
                * *(Optional)* Thêm nút/tự động chuyển hướng đến trang Đăng Nhập sau vài giây.
            * **Thất bại (4xx/5xx):**
                * Enable lại nút. Ẩn loading.
                * Hiển thị lỗi trong `feedback-step2`:
                    * `EmailNotFoundException`: "Email không tồn tại." (Ít xảy ra nếu bước 1 thành công)
                    * `InvalidOTPException`: "Mã OTP không hợp lệ."
                    * `OTPExpiredException`: "Mã OTP đã hết hạn. Vui lòng yêu cầu lại."
                    * Lỗi khác: "Đặt lại mật khẩu thất bại."

---

## Xử Lý Trạng Thái & Phản Hồi (State Management & Feedback)

* Quản lý trạng thái để hiển thị Giai đoạn 1 hoặc Giai đoạn 2 (`currentStep`).
* Lưu trữ `email` nhập ở Giai đoạn 1 để sử dụng cho API call ở Giai đoạn 2.
* Quản lý trạng thái loading cho các nút.
* Hiển thị thông báo lỗi/thành công/hướng dẫn phù hợp với từng giai đoạn.








