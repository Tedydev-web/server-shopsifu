# Module Auth - Quản lý Xác thực

## Tổng quan

Module này cung cấp các chức năng xác thực và quản lý tài khoản, bao gồm đăng ký, đăng nhập, quên mật khẩu và xác thực hai yếu tố.

## Cấu trúc File

- **auth.controller.ts**: Chứa các endpoints API
- **auth.service.ts**: Xử lý logic nghiệp vụ chính
- **auth.repo.ts**: Tương tác với cơ sở dữ liệu thông qua Prisma
- **auth.model.ts**: Định nghĩa các schema Zod cho DTO và models
- **auth.dto.ts**: Định nghĩa các DTO cho request và response
- **auth.module.ts**: Module NestJS cấu hình các providers
- **error.model.ts**: Định nghĩa các thông báo lỗi và exception
- **google.service.ts**: Xử lý đăng nhập qua Google
- **roles.service.ts**: Quản lý vai trò người dùng

## Quy trình Xác thực

### Đăng ký tài khoản

1. Gửi OTP: `POST /auth/otp` (type=REGISTER)
2. Đăng ký: `POST /auth/register` với mã OTP

### Đăng nhập

1. Đăng nhập: `POST /auth/login`
2. Refresh token: `POST /auth/refresh-token`
3. Đăng xuất: `POST /auth/logout`

### Quên mật khẩu

1. Gửi OTP: `POST /auth/otp` (type=FORGOT_PASSWORD)
2. Xác thực OTP: `POST /auth/verify-code`
3. Đặt lại mật khẩu: `POST /auth/reset-password`

## Tính năng Bảo mật

### Mật khẩu

- Yêu cầu: ít nhất 8 ký tự, 1 chữ hoa, 1 chữ thường, 1 số, 1 ký tự đặc biệt
- Mật khẩu được mã hóa sử dụng bcrypt trước khi lưu vào cơ sở dữ liệu

### OTP

- Mã OTP được mã hóa với salt trước khi lưu vào cơ sở dữ liệu
- Giới hạn số lần thử nhập OTP
- Tự động hết hạn sau khoảng thời gian cấu hình

### Email

- Email được chuẩn hóa về chữ thường trước khi xử lý và lưu vào cơ sở dữ liệu

### Rate Limiting

- Giới hạn số lần gọi API nhạy cảm như đăng nhập, đăng ký, gửi OTP

### Thiết bị và Token

- Theo dõi thiết bị đăng nhập
- Liên kết token với thiết bị cụ thể
- Phát hiện truy cập trái phép qua token đã sử dụng

## Xử lý Lỗi

Sử dụng `error.model.ts` để định nghĩa:

- Thông báo lỗi cho từng loại lỗi (password, email, OTP, token)
- Các exception cụ thể cho mỗi trường hợp lỗi
- Định dạng phản hồi lỗi nhất quán
