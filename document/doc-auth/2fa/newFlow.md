API Specification for Authentication Flow

1. Send OTP API

Endpoint: POST /auth/otp
Request Body:{
"email": "user@example.com",
"type": "LOGIN" // hoặc "REGISTER", "FORGOT_PASSWORD", "DISABLE_2FA"
}

Response:{
"message": "OTP sent to email"
}

Security Notes:
Lưu OTP vào bảng VerificationCode với email, code, type, và expiresAt (5 phút).
Lưu ip và userAgent để kiểm tra khi xác thực.
Giới hạn 5 lần gửi OTP/giờ cho mỗi email.

2. Login API

Endpoint: POST /auth/login
Request Body:{
"email": "user@example.com",
"password": "password123"
}

Response:
Chưa bật 2FA:{
"accessToken": "jwt_access_token",
"refreshToken": "jwt_refresh_token"
}

Đã bật 2FA:{
"loginSessionToken": "uuid_or_jwt",
"message": "2FA required",
"2faEnabled": true
}

Security Notes:
Kiểm tra email và mật khẩu trong bảng User.
Nếu 2FA bật, tạo loginSessionToken (UUID hoặc JWT, thời hạn 5 phút), lưu vào bảng OtpToken với type: LOGIN, email, userId.

3. 2FA Verify API

Endpoint: POST /auth/2fa/verify
Request Body:{
"loginSessionToken": "uuid_or_jwt",
"method": "TOTP" | "OTP",
"code": "123456"
}

Response:{
"accessToken": "jwt_access_token",
"refreshToken": "jwt_refresh_token"
}

Security Notes:
Xác minh loginSessionToken trong bảng OtpToken, lấy userId và email.
Nếu method: "TOTP", xác thực mã với totpSecret từ bảng User.
Nếu method: "OTP", xác thực mã trong bảng VerificationCode với email và type: LOGIN.
Nếu hợp lệ, tạo accessToken và refreshToken, lưu refreshToken

Key Citations

OneLogin Developers Multi-Factor Authentication Overview
FusionAuth Login API
OWASP Multifactor Authentication Cheat Sheet
Rublon 2FA Security Best Practices
