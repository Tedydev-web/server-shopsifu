# 2FA - Two Factor Authentication

## Tạo mã 2FA

- @POST(`/2fa/setup`)
- Backend sẽ trả về 1 mã Key URI để FE tạo QR Code, bonus thêm secret key
- Một khi đã tạo mã 2FA thì lúc login, phải nhập mã 2FA để xác thực (hoặc OTP Code phòng trường hợp đánh mất điện thoại)

## Vô hiệu hóa 2FA

- @POST(`/2fa/disable`)
- Xóa `totpSecret` của user trong DB

## Xác thực 2FA hoặc OTP Code

- Xảy ra ở API Login và API vô hiệu hóa 2FA

Với Flow này, sẽ đảm bảo việc có 1 giải pháp backup trong trường hợp người dùng đánh mất điện thoại hoặc không thể truy cập vào mã 2FA
