# Giao Diện Người Dùng: Đăng Nhập (Login)

**File:** `ui-login.md`
**Ngày tạo:** 2025-04-30

## Mục Tiêu (Goal)

Cho phép người dùng đã có tài khoản đăng nhập vào hệ thống bằng email và mật khẩu. Hỗ trợ luồng xác thực 2 yếu tố (2FA) nếu người dùng đã kích hoạt.

---

## API Endpoint Liên Quan (Related API Endpoint)

1.  `POST /auth/login`
2.  `POST /auth/send-otp` (với `type: TypeOfVerificationCode.LOGIN`, chỉ khi cần xác thực 2FA qua email)
   
---

## Luồng Logic Backend (Backend Logic Flow - Summary)

1.  **`login`**:
    * Tìm user bằng `email`. Ném `EmailNotFoundException` nếu không tìm thấy.
    * So sánh `password` cung cấp với hash trong DB. Ném `InvalidPasswordException` nếu không khớp.
    * Kiểm tra xem user có `totpSecret` (đã bật 2FA) không:
        * **Nếu CÓ `totpSecret`:**
            * Kiểm tra xem request có gửi kèm `totpCode` hoặc `code` (OTP email) không.
            * Nếu **KHÔNG** có cả hai, ném `InvalidTOTPAndCodeException`.
            * Nếu **CÓ `totpCode`:** Gọi `twoFactorService.verifyTOTP`. Ném `InvalidTOTPException` nếu mã không hợp lệ.
            * Nếu **CÓ `code` (và không có `totpCode`):** Gọi `validateVerificationCode` với `type = LOGIN`. Ném `InvalidOTPException` hoặc `OTPExpiredException` nếu không hợp lệ.
        * **Nếu KHÔNG có `totpSecret`:** Bỏ qua bước kiểm tra 2FA.
    * Tạo bản ghi `Device` mới với `userId`, `userAgent`, `ip`.
    * Gọi `generateTokens` để tạo `accessToken` và `refreshToken`.
    * Lưu `refreshToken` vào DB.
    * Trả về `{ accessToken, refreshToken }`.

2.  **`sendOTP (LOGIN)`**: *(Chỉ được gọi khi UI cần gửi OTP cho bước 2FA)*
    * Tìm user bằng `email`.
    * Tạo mã `code` (OTP).
    * Lưu `email`, `code`, `type = LOGIN`, và `expiresAt`.
    * Gửi email chứa `code`. Ném `FailedToSendOTPException` nếu thất bại.
    * Trả về thông báo thành công.

---

## Luồng Tương Tác Người Dùng (User Interaction Workflow)

1.  Người dùng nhập **Email** và **Mật Khẩu**.

2.  Frontend thực hiện **Client-Side Validation** (email, required fields).

3.  Người dùng nhấn **"Đăng Nhập"**.
    * **Frontend:** Disable nút "Đăng Nhập". Hiển thị loading.
    * **Frontend Call API (Lần 1):** `POST /auth/login` với `{ email, password }`.
    * **Xử lý Response:**
        * **Thành công (2xx - Có tokens):**
            * Ẩn loading.
            * Lưu `accessToken`, `refreshToken` (an toàn, ví dụ: httpOnly cookie cho refresh, memory/localStorage cho access).
            * Chuyển hướng người dùng vào trang chính/dashboard.
        * **Thất bại (401 - `InvalidTOTPAndCodeException`):**
            * Ẩn loading. Enable nút "Đăng Nhập".
            * **Hiển thị Vùng Xác Thực 2FA**.
            * Xóa các thông báo lỗi cũ.
        * **Thất bại (4xx/5xx - Lỗi khác):**
            * Ẩn loading. Enable nút "Đăng Nhập".
            * Hiển thị thông báo lỗi trong `form-feedback`:
                * `EmailNotFoundException`: "Email không tồn tại."
                * `InvalidPasswordException`: "Mật khẩu không chính xác."
                * Lỗi khác: "Đăng nhập thất bại. Vui lòng thử lại."

4.  **Nếu Vùng Xác Thực 2FA được hiển thị:**
    * **Lựa chọn 1: Người dùng nhập mã TOTP**
        * Người dùng nhập mã vào **TOTP Input**.
        * Người dùng nhấn **"Xác Thực"**.
            * **Frontend:** Disable nút "Xác Thực". Hiển thị loading.
            * **Frontend Call API (Lần 2):** `POST /auth/login` với `{ email, password, totpCode: totpCodeValue }`.
            * **Xử lý Response:**
                * **Thành công (2xx - Có tokens):** Lưu tokens, chuyển hướng (như bước 3 thành công).
                * **Thất bại (4xx/5xx):** Enable nút "Xác Thực". Ẩn loading. Hiển thị lỗi trong `form-feedback`:
                    * `InvalidTOTPException`: "Mã xác thực (TOTP) không hợp lệ."
                    * Lỗi khác: "Xác thực thất bại."
    
    * **Lựa chọn 2: Người dùng yêu cầu OTP qua Email**
        * Người dùng nhấn **"Gửi mã xác thực qua Email"**.
            * **Frontend:** Disable nút này. Hiển thị loading nhỏ bên cạnh.
            * **Frontend Call API:** `POST /auth/send-otp` với `{ email: emailValue, type: TypeOfVerificationCode.LOGIN }`.
            * **Xử lý Response:**
                * **Thành công (2xx):** Enable lại nút. Ẩn loading. Hiển thị thông báo trong `otp-2fa-feedback` ("Đã gửi mã OTP."). **Enable** trường **OTP Email Input**. Focus vào đó.
                * **Thất bại (4xx/5xx):** Enable lại nút. Ẩn loading. Hiển thị lỗi trong `otp-2fa-feedback` ("Gửi mã thất bại.").
        * Người dùng nhập mã OTP nhận được vào **OTP Email Input**.
        * Người dùng nhấn **"Xác Thực"**.
            * **Frontend:** Disable nút "Xác Thực". Hiển thị loading.
            * **Frontend Call API (Lần 2):** `POST /auth/login` với `{ email, password, code: otpCodeValue }`.
            * **Xử lý Response:**
                * **Thành công (2xx - Có tokens):** Lưu tokens, chuyển hướng.
                * **Thất bại (4xx/5xx):** Enable nút "Xác Thực". Ẩn loading. Hiển thị lỗi trong `form-feedback`:
                    * `InvalidOTPException`: "Mã xác thực (Email OTP) không hợp lệ."
                    * `OTPExpiredException`: "Mã xác thực (Email OTP) đã hết hạn."
                    * Lỗi khác: "Xác thực thất bại."

---

## Xử Lý Trạng Thái & Phản Hồi (State Management & Feedback)

* Quản lý trạng thái `isLoading` cho các nút.
* Quản lý trạng thái hiển thị của Vùng Xác Thực