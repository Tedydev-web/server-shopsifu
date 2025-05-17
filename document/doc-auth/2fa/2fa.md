# 2FA - Two Factor Authentication

## Quy trình thiết lập 2FA (Flow hiện đại và an toàn)

1. **Tạo mã 2FA tạm thời**

   - `POST /auth/2fa/setup`
   - Backend trả về:
     - secret key: mã bí mật TOTP
     - uri: dùng để tạo QR code
     - setupToken: token để xác nhận setup

2. **Xác nhận mã 2FA**

   - `POST /auth/2fa/confirm-setup`
   - Người dùng quét QR code bằng ứng dụng Authenticator
   - Nhập mã TOTP vào trường totpCode
   - Gửi setupToken cùng mã TOTP để xác nhận thiết lập
   - Backend trả về mã khôi phục (recovery codes) khi thiết lập thành công

3. **Phương pháp khôi phục thay thế**
   - **Recovery Codes**: Mã khôi phục được tạo khi thiết lập 2FA
   - **Email OTP**: Gửi OTP qua email để xác thực

## Vô hiệu hóa 2FA

- `POST /auth/2fa/disable`
- Xóa `totpSecret` của user trong DB
- Xác thực bằng cách sử dụng TOTP code hoặc OTP code

## Xác thực khi đăng nhập với 2FA

1. **Đăng nhập bước 1: Xác thực mật khẩu**

   - `POST /auth/login`: Nếu 2FA đã bật, trả về loginSessionToken
   - Chỉ kiểm tra email và mật khẩu tại bước này

2. **Đăng nhập bước 2: Xác thực 2FA**
   - `POST /auth/2fa/verify`: Có 3 phương thức xác thực
     - `type: "TOTP"`: Xác thực bằng mã từ ứng dụng Authenticator
     - `type: "OTP"`: Xác thực bằng mã gửi qua email
     - `type: "RECOVERY"`: Xác thực bằng một trong các recovery codes

Flow này đảm bảo:

1. Chỉ kích hoạt 2FA sau khi xác nhận quét mã thành công
2. Có nhiều phương án dự phòng (recovery codes và email OTP)
3. Recovery code chỉ dùng để bypass 2FA sau khi xác thực mật khẩu thành công
4. Mỗi recovery code chỉ dùng được một lần
