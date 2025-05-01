# Giao Diện Người Dùng: Đăng Ký (Register)

**File:** `ui-register.md`
**Ngày tạo:** 2025-04-30

---

## Mục Tiêu (Goal)

Giao diện này cho phép người dùng mới tạo tài khoản bằng cách cung cấp thông tin cá nhân và xác thực địa chỉ email thông qua mã OTP.

---

## API Endpoint Liên Quan (Related API Endpoint)

1.  `POST /auth/send-otp` (với `type: TypeOfVerificationCode.REGISTER`)
2.  `POST /auth/register`

---

## Luồng Logic Backend (Backend Logic Flow - Summary)

1.  **`sendOTP (REGISTER)`**:
    * Kiểm tra xem `email` đã tồn tại trong `SharedUserRepository` chưa.
    * Nếu **đã tồn tại**, ném lỗi `EmailAlreadyExistsException`.
    * Nếu **chưa tồn tại**:
        * Tạo mã `code` (OTP).
        * Lưu `email`, `code`, `type = REGISTER`, và `expiresAt` vào bảng Verification Code.
        * Gửi email chứa `code` cho người dùng. Ném `FailedToSendOTPException` nếu gửi thất bại.
        * Trả về thông báo thành công.
2.  **`register`**:
    * Gọi `validateVerificationCode` để kiểm tra `email`, `code`, và `type = REGISTER`.
        * Ném `InvalidOTPException` nếu không tìm thấy bản ghi phù hợp.
        * Ném `OTPExpiredException` nếu mã đã hết hạn.
    * Lấy `clientRoleId`.
    * Hash mật khẩu (`password`).
    * Tạo bản ghi người dùng mới (`User`) với thông tin đã cung cấp.
    * Xóa bản ghi Verification Code đã sử dụng.
    * Trả về thông tin người dùng vừa tạo.
    * *Catch Block:* Ném `EmailAlreadyExistsException` nếu có lỗi unique constraint khi tạo user (trường hợp hiếm xảy ra nếu `sendOTP` đã kiểm tra).

---

## Luồng Tương Tác Người Dùng (User Interaction Workflow)

1.  Người dùng nhập **Địa chỉ Email**.
2.  Người dùng nhấn nút **"Gửi Mã Xác Nhận"**.
    * **Frontend:** Disable nút "Gửi Mã Xác Nhận". Hiển thị trạng thái loading.
    * **Frontend Call API:** `POST /auth/send-otp` với `{ email: emailValue, type: TypeOfVerificationCode.REGISTER }`.
    * **Xử lý Response:**
        * **Thành công (2xx):**
            * Enable nút "Gửi Mã Xác Nhận" lại. Ẩn loading.
            * Hiển thị thông báo thành công trong `otp-feedback` (ví dụ: "Đã gửi mã OTP. Vui lòng kiểm tra email.").
            * **Enable** trường **OTP Input**. Focus vào trường này.
        * **Thất bại (4xx/5xx):**
            * Enable nút "Gửi Mã Xác Nhận" lại. Ẩn loading.
            * Hiển thị thông báo lỗi trong `otp-feedback` dựa trên exception backend trả về:
                * `EmailAlreadyExistsException`: "Email này đã được đăng ký."
                * `FailedToSendOTPException`: "Không thể gửi mã OTP vào lúc này. Vui lòng thử lại."
                * Lỗi khác: "Đã có lỗi xảy ra."
3.  Người dùng nhập **Mã Xác Nhận OTP** và các thông tin còn lại (`name`, `phoneNumber`, `password`, `confirmPassword`).
4.  Frontend thực hiện **Client-Side Validation** (định dạng email, các trường bắt buộc, mật khẩu khớp).
5.  Người dùng nhấn nút **"Đăng Ký"**.
    * **Frontend:** Disable nút "Đăng Ký". Hiển thị trạng thái loading.
    * **Frontend Call API:** `POST /auth/register` với `{ email, code, name, phoneNumber, password }`.
    * **Xử lý Response:**
        * **Thành công (2xx):**
            * Ẩn loading.
            * Hiển thị thông báo thành công ("Đăng ký thành công!").
            * Chuyển hướng người dùng đến trang Đăng Nhập (`/login`) hoặc trang chào mừng.
        * **Thất bại (4xx/5xx):**
            * Enable nút "Đăng Ký" lại. Ẩn loading.
            * Hiển thị thông báo lỗi trong `form-feedback` dựa trên exception backend trả về:
                * `InvalidOTPException`: "Mã OTP không hợp lệ."
                * `OTPExpiredException`: "Mã OTP đã hết hạn. Vui lòng yêu cầu mã mới."
                * `EmailAlreadyExistsException`: "Email này đã được đăng ký." (Trường hợp hy hữu)
                * Lỗi khác: "Đăng ký thất bại. Vui lòng thử lại."

---

## Xử Lý Trạng Thái & Phản Hồi (State Management & Feedback)

* Sử dụng state để quản lý trạng thái loading của các nút (`isSendingOtp`, `isRegistering`).
* Sử dụng state để lưu trữ thông báo lỗi/thành công cho từng phần (OTP, Form chung).
* Disable các trường/nút không cần thiết trong quá trình xử lý API call.
* Clear thông báo lỗi khi người dùng bắt đầu nhập lại thông tin.
