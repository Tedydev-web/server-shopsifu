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

## Các Thành Phần Giao Diện (UI Components)

* **Form Đăng Ký (`<form>`)**:
    * **Tiêu đề**: "Đăng Ký Tài Khoản"
    * **Email Input (`<input type="email" name="email" required>`)**:
        * Label: "Địa chỉ Email"
        * Placeholder: "nhapemail@example.com"
    * **Nút Gửi OTP (`<button type="button" id="send-otp-btn">`)**:
        * Text: "Gửi Mã Xác Nhận"
        * *Trạng thái:* Disable khi đang gửi OTP.
    * **Vùng Thông Báo OTP (`<div class="otp-feedback">`)**: Hiển thị thông báo sau khi nhấn "Gửi Mã Xác Nhận" (ví dụ: "Đã gửi mã OTP đến email của bạn", hoặc lỗi "Email đã tồn tại").
    * **OTP Input (`<input type="text" name="code" required disabled>`)**:
        * Label: "Mã Xác Nhận OTP"
        * Placeholder: "Nhập mã OTP từ email"
        * *Trạng thái:* Enable *sau khi* nhấn "Gửi Mã Xác Nhận" thành công.
    * **Tên Input (`<input type="text" name="name" required>`)**:
        * Label: "Họ và Tên"
        * Placeholder: "Nguyễn Văn A"
    * **Số Điện Thoại Input (`<input type="tel" name="phoneNumber">`)**:
        * Label: "Số Điện Thoại" (Optional hoặc Required tùy yêu cầu)
        * Placeholder: "09xxxxxxxx"
    * **Mật Khẩu Input (`<input type="password" name="password" required>`)**:
        * Label: "Mật Khẩu"
        * Placeholder: "Nhập mật khẩu"
    * **Xác Nhận Mật Khẩu Input (`<input type="password" name="confirmPassword" required>`)**:
        * Label: "Xác Nhận Mật Khẩu"
        * Placeholder: "Nhập lại mật khẩu"
    * **Nút Đăng Ký (`<button type="submit" id="register-btn">`)**:
        * Text: "Đăng Ký"
        * *Trạng thái:* Disable khi đang xử lý đăng ký.
* **Vùng Thông Báo Chung (`<div class="form-feedback">`)**: Hiển thị lỗi cuối cùng (ví dụ: "Mã OTP không hợp lệ", "Mật khẩu không khớp") hoặc thông báo thành công chung.
* **Liên kết Đăng Nhập (`<a href="/login">`)**: "Đã có tài khoản? Đăng nhập ngay"

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

---

## Validation Phía Client (Client-Side Validation)

* Kiểm tra định dạng email hợp lệ.
* Kiểm tra các trường `required` không bị trống.
* Kiểm tra `password` và `confirmPassword` phải trùng khớp.
* *(Optional)* Kiểm tra độ mạnh mật khẩu (độ dài, ký tự đặc biệt,...).

---

## Lưu Ý Cho Intern (Notes for Intern)

* Luồng đăng ký này yêu cầu 2 bước API call: gửi OTP trước, sau đó mới đăng ký. Đảm bảo UI phản ánh đúng trình tự này.
* Xử lý cẩn thận các trạng thái `disabled` của input và button để tránh người dùng thao tác sai.
* Hiển thị thông báo lỗi rõ ràng, tương ứng với lỗi trả về từ backend.
* Focus vào input `code` sau khi gửi OTP thành công để cải thiện trải nghiệm người dùng.