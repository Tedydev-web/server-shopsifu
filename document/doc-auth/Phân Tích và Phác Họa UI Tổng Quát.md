# Phân Tích và Phác Họa UI

---

## 1. Tổng Quan Về Các Chức Năng Chính

Các chức năng xác thực người dùng quan trọng, bao gồm:

- **Đăng ký (Register)**: Tạo tài khoản mới.
- **Gửi mã OTP (Send OTP)**: Gửi mã xác minh qua email.
- **Đăng nhập (Login)**: Xác thực và truy cập hệ thống.
- **Làm mới token (Refresh Token)**: Cập nhật token truy cập.
- **Đăng xuất (Logout)**: Thoát khỏi hệ thống.
- **Quên mật khẩu (Forgot Password)**: Đặt lại mật khẩu.
- **Thiết lập xác thực hai yếu tố (Setup 2FA)**: Kích hoạt 2FA.
- **Vô hiệu hóa xác thực hai yếu tố (Disable 2FA)**: Tắt 2FA.

Mỗi chức năng có logic và dữ liệu đầu vào riêng, đòi hỏi UI phải được thiết kế phù hợp để hỗ trợ người dùng thực hiện các tác vụ này một cách dễ dàng và an toàn.

---

## 2. Phân Tích Chi Tiết Từng Chức Năng

### 2.1. Đăng Ký (Register)
- **API Endpoint**: `POST /auth/register`
- **Dữ liệu đầu vào**:
  - `email`: string
  - `name`: string
  - `phoneNumber`: string
  - `password`: string
  - `code`: string (mã OTP)
- **Logic**:
  - Xác thực mã OTP loại `REGISTER`.
  - Tạo người dùng mới với vai trò "client".
  - Xóa mã OTP sau khi đăng ký thành công.
- **Yêu cầu UI**:
  - Form gồm các trường: email, tên, số điện thoại, mật khẩu, mã OTP.
  - Nút gửi form.

### 2.2. Gửi Mã OTP (Send OTP)
- **API Endpoint**: `POST /auth/send-otp`
- **Dữ liệu đầu vào**:
  - `email`: string
  - `type`: `TypeOfVerificationCodeType` (REGISTER, FORGOT_PASSWORD, LOGIN, DISABLE_2FA)
- **Logic**:
  - Kiểm tra email tồn tại hay chưa dựa trên loại OTP.
  - Tạo và gửi mã OTP qua email.
- **Yêu cầu UI**:
  - Form với trường email và tùy chọn loại OTP (dropdown hoặc nút riêng).
  - Nút gửi OTP.

### 2.3. Đăng Nhập (Login)
- **API Endpoint**: `POST /auth/login`
- **Dữ liệu đầu vào**:
  - `email`: string
  - `password`: string
  - `totpCode`: string (tùy chọn, nếu 2FA bật)
  - `code`: string (tùy chọn, mã OTP nếu 2FA bật)
  - `userAgent`: string (từ headers)
  - `ip`: string (từ headers)
- **Logic**:
  - Xác thực email và mật khẩu.
  - Nếu 2FA bật, yêu cầu mã TOTP hoặc OTP.
  - Tạo thiết bị và tokens.
- **Yêu cầu UI**:
  - Form gồm email, mật khẩu.
  - Nếu 2FA bật, hiển thị thêm ô nhập mã TOTP hoặc OTP.
  - Nút đăng nhập.

### 2.4. Làm Mới Token (Refresh Token)
- **API Endpoint**: `POST /auth/refresh-token`
- **Dữ liệu đầu vào**:
  - `refreshToken`: string
  - `userAgent`: string (từ headers)
  - `ip`: string (từ headers)
- **Logic**:
  - Xác thực refresh token.
  - Cập nhật thiết bị và tạo tokens mới.
- **Yêu cầu UI**:
  - Không cần UI trực tiếp (xử lý backend).

### 2.5. Đăng Xuất (Logout)
- **API Endpoint**: `POST /auth/logout`
- **Dữ liệu đầu vào**:
  - `refreshToken`: string
- **Logic**:
  - Xác thực và xóa refresh token.
  - Cập nhật trạng thái thiết bị.
- **Yêu cầu UI**:
  - Nút đăng xuất.

### 2.6. Quên Mật Khẩu (Forgot Password)
- **API Endpoint**: `POST /auth/forgot-password`
- **Dữ liệu đầu vào**:
  - `email`: string
  - `code`: string (mã OTP)
  - `newPassword`: string
- **Logic**:
  - Xác thực email và mã OTP loại `FORGOT_PASSWORD`.
  - Cập nhật mật khẩu mới.
- **Yêu cầu UI**:
  - Form gồm email, mã OTP, mật khẩu mới.
  - Nút gửi form.

### 2.7. Thiết Lập Xác Thực Hai Yếu Tố (Setup 2FA)
- **API Endpoint**: `POST /auth/setup-2fa`
- **Dữ liệu đầu vào**:
  - Không có (dùng `userId` từ token).
- **Logic**:
  - Tạo secret và URI cho 2FA.
  - Lưu secret vào database.
- **Yêu cầu UI**:
  - Trang hiển thị mã QR (từ URI) và secret.
  - Nút kích hoạt.

### 2.8. Vô Hiệu Hóa Xác Thực Hai Yếu Tố (Disable 2FA)
- **API Endpoint**: `POST /auth/disable-2fa`
- **Dữ liệu đầu vào**:
  - `totpCode`: string (tùy chọn)
  - `code`: string (tùy chọn, mã OTP)
- **Logic**:
  - Xác thực mã TOTP hoặc OTP loại `DISABLE_2FA`.
  - Xóa secret 2FA.
- **Yêu cầu UI**:
  - Form nhập mã TOTP hoặc OTP.
  - Nút vô hiệu hóa.

---

## 3. Workflow và Luồng Dữ Liệu

### 3.1. Đăng Ký Người Dùng Mới
1. Người dùng nhập email, yêu cầu OTP (`REGISTER`).
2. Nhận OTP qua email.
3. Điền form đăng ký (email, tên, số điện thoại, mật khẩu, OTP).
4. Gửi form.
5. Nhận thông báo thành công/lỗi.

### 3.2. Đăng Nhập
1. Nhập email và mật khẩu.
2. Nếu 2FA bật, nhập mã TOTP hoặc OTP (`LOGIN`).
3. Gửi form.
4. Nhận tokens và chuyển hướng.

### 3.3. Quên Mật Khẩu
1. Nhập email, yêu cầu OTP (`FORGOT_PASSWORD`).
2. Nhận OTP qua email.
3. Điền form (email, OTP, mật khẩu mới).
4. Gửi form.
5. Nhận thông báo thành công/lỗi.

### 3.4. Thiết Lập 2FA
1. Truy cập trang thiết lập 2FA.
2. Hiển thị mã QR và secret.
3. Quét mã QR hoặc nhập secret vào ứng dụng authenticator.
4. Xác nhận mã TOTP.

### 3.5. Vô Hiệu Hóa 2FA
1. Truy cập trang vô hiệu hóa 2FA.
2. Nhập mã TOTP hoặc yêu cầu OTP (`DISABLE_2FA`).
3. Gửi form.
4. Nhận thông báo thành công/lỗi.

---

## 4. Các Thành Phần UI Cần Thiết

- **Form Đăng Ký**: Email, tên, số điện thoại, mật khẩu, OTP.
- **Form Đăng Nhập**: Email, mật khẩu, (TOTP/OTP nếu 2FA bật).
- **Form Gửi OTP**: Email, loại OTP.
- **Form Quên Mật Khẩu**: Email, OTP, mật khẩu mới.
- **Trang Thiết Lập 2FA**: Mã QR, secret.
- **Form Vô Hiệu Hóa 2FA**: TOTP hoặc OTP.
- **Nút Đăng Xuất**: Gọi API logout.

---

## 5. Lưu Ý Khi Thiết Kế UI

- **Bảo mật**: Che giấu mật khẩu, mã OTP.
- **Thông báo lỗi**: Hiển thị rõ ràng (email đã tồn tại, OTP hết hạn, v.v.).
- **Xác thực đầu vào**: Kiểm tra dữ liệu phía client.
- **Trải nghiệm người dùng**: Luồng mượt mà (tự động chuyển sang nhập OTP sau khi gửi yêu cầu).
- **Hỗ trợ 2FA**: Hướng dẫn quét mã QR và sử dụng authenticator.

---

## Kết Luận

Để xây dựng UI, bạn cần thiết kế các form, trang và luồng người dùng tương ứng với từng chức năng, đảm bảo tính bảo mật và trải nghiệm mượt mà. Phác thảo này là nền tảng để bạn bắt đầu triển khai giao diện chuyên nghiệp và hiệu quả.