# Quy trình quên mật khẩu mới

## Tổng quan

Quy trình đặt lại mật khẩu đã được cải tiến để tăng cường bảo mật bằng cách:

1. Gán token đặt lại mật khẩu với thiết bị cụ thể
2. Loại bỏ endpoint `forgot-password` và chỉ sử dụng quy trình `verify-code` -> `reset-password`
3. Thêm xác thực device khi đặt lại mật khẩu

## Luồng xử lý

### 1. Gửi OTP

- **Endpoint**: `POST /auth/otp`
- **Request body**:
  ```json
  {
    "email": "example@email.com",
    "type": "FORGOT_PASSWORD"
  }
  ```
- **Xử lý**:
  - Kiểm tra email có tồn tại trong hệ thống
  - Tạo mã OTP và lưu vào database
  - Gửi email chứa mã OTP đến người dùng
- **Response**:
  ```json
  {
    "message": "Gửi mã OTP thành công"
  }
  ```

### 2. Xác thực OTP

- **Endpoint**: `POST /auth/verify-code`
- **Request body**:
  ```json
  {
    "email": "example@email.com",
    "code": "123456",
    "type": "FORGOT_PASSWORD"
  }
  ```
- **Xử lý**:
  - Kiểm tra mã OTP có hợp lệ và chưa hết hạn
  - Tạo một OtpToken mới, liên kết với thiết bị hiện tại
  - Xóa mã OTP đã sử dụng
- **Response**:
  ```json
  {
    "token": "uuid-token-string",
    "expiresAt": "2023-01-01T00:00:00.000Z"
  }
  ```

### 3. Đặt lại mật khẩu

- **Endpoint**: `POST /auth/reset-password`
- **Request body**:
  ```json
  {
    "token": "uuid-token-string",
    "newPassword": "newPassword123",
    "confirmNewPassword": "newPassword123"
  }
  ```
- **Xử lý**:
  - Kiểm tra token có hợp lệ và chưa hết hạn
  - Kiểm tra token có đúng loại (FORGOT_PASSWORD)
  - Đổi mật khẩu và cập nhật trạng thái thiết bị
- **Response**:
  ```json
  {
    "message": "Đổi mật khẩu thành công"
  }
  ```

## Lưu ý bảo mật

- Token đặt lại mật khẩu chỉ có hiệu lực trong thời gian giới hạn (mặc định 15 phút)
- Token gắn liền với thiết bị gửi yêu cầu, ngăn chặn tấn công từ thiết bị khác
- Mỗi token chỉ được sử dụng một lần, sau đó sẽ bị xóa
- Mọi thao tác đều được ghi log để phát hiện hoạt động đáng ngờ
