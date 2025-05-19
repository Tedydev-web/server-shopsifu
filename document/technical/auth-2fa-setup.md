# Endpoint: `POST /auth/2fa/setup` - Khởi tạo Cài đặt 2FA (TOTP)

## 1. Mô tả

Endpoint này cho phép người dùng đã đăng nhập khởi tạo quá trình cài đặt Xác thực Hai Yếu tố dựa trên Thời gian (TOTP - Time-based One-Time Password) cho tài khoản của họ. Hệ thống sẽ tạo ra một mã bí mật (secret key) mới, một URL mã QR (otpauth URL), và lưu trữ mã bí mật này tạm thời (chưa kích hoạt cho user) chờ xác minh.

Người dùng sẽ sử dụng mã QR (hoặc mã bí mật dạng text) để thêm tài khoản vào ứng dụng xác thực của họ (ví dụ: Google Authenticator, Authy).

## 2. Decorators

- `@UseGuards(AccessTokenGuard)`: Yêu cầu `accessToken` hợp lệ. Chỉ người dùng đã đăng nhập mới có thể cài đặt 2FA.
- `@HttpCode(HttpStatus.OK)`: Trả về HTTP status 200 khi khởi tạo thành công.
- `@ZodSerializerDto(Setup2FAResDTO)`: Response trả về chứa thông tin cần thiết để FE hiển thị mã QR.
- `@Throttle({ short: { limit: 3, ttl: 60000 } })`: Giới hạn tần suất truy cập.

## 3. Request

- **Body:** Không yêu cầu body.
- **Cookies (BE đọc):**
  - `access_token`: Được `AccessTokenGuard` sử dụng để xác thực người dùng.
- **Headers (Tự động lấy bởi Guards/Decorators):**
  - `Authorization: Bearer <access_token>`: Được xử lý bởi `AccessTokenGuard`.

## 4. Response

**4.1. Thành công:**

- **Status Code:** 200 OK
- \*\*Body (Serialized bởi `Setup2FAResSchema`):
  ```json
  {
    "statusCode": 200,
    "message": "Auth.2FA.SetupInitiated", // i18n key
    "data": {
      "message": "Auth.2FA.SetupInitiated",
      "otpauthUrl": "otpauth://totp/Shopsifu:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Shopsifu&algorithm=SHA1&digits=6&period=30",
      "base32Secret": "JBSWY3DPEHPK3PXP",
      "setupToken": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" // UUID token để xác minh ở bước sau
    }
  }
  ```
  - `otpauthUrl`: URL mà ứng dụng xác thực có thể sử dụng để tự động cấu hình (thường được hiển thị dưới dạng mã QR).
  - `base32Secret`: Mã bí mật dưới dạng Base32, người dùng có thể nhập thủ công vào ứng dụng xác thực.
  - `setupToken`: Một UUID token được tạo ra để liên kết với quá trình cài đặt này. Nó sẽ được sử dụng trong endpoint `/auth/2fa/verify` để hoàn tất việc kích hoạt 2FA.

**4.2. Lỗi:**

- **401 Unauthorized (`UnauthorizedAccessException`):** Nếu `accessToken` không hợp lệ hoặc hết hạn.
- **409 Conflict (`TwoFactorAlreadyEnabledException`):** Nếu người dùng đã kích hoạt 2FA trước đó.
  ```json
  {
    "type": "https://api.shopsifu.live/errors/conflict",
    "title": "Conflict",
    "status": 409,
    "description": "Error.Auth.2FA.AlreadyEnabled",
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid"
  }
  ```
- **500 Internal Server Error (`OtpGenerationException`):** Nếu có lỗi trong quá trình tạo mã bí mật 2FA hoặc lưu `VerificationToken` cho việc cài đặt.

## 5. Luồng Hoạt động (Backend - `TwoFactorAuthService.setup` trong `AuthService`)

1.  **Xác thực User:** `AccessTokenGuard` xác thực người dùng. `req.user` chứa thông tin `userId` và `email`.
2.  **Audit Logging:** Bắt đầu ghi log (`action: 'USER_2FA_SETUP_INITIATED'`).
3.  **Kiểm tra User:** Gọi `AuthRepository.findUserById(req.user.userId)` để lấy thông tin user hiện tại.
    - **Nếu `user.twoFactorEnabled` là `true`:** Ném `TwoFactorAlreadyEnabledException`.
4.  **Tạo Thông tin 2FA (TOTP):**
    - Gọi `Shared2FAService.generateTwoFactorSecret(req.user.email, envConfig.TWO_FACTOR_AUTHENTICATOR_NAME)`.
      - Dịch vụ này sẽ tạo ra một `secret` (mã bí mật ngẫu nhiên, ví dụ 20 bytes, sau đó mã hóa Base32) và một `otpauthUrl`.
5.  **Tạo `setupToken` (UUID):** Tạo một `setupTokenDb` (UUID) mới.
6.  **Lưu `VerificationToken` cho Cài đặt 2FA:**
    - Tạo và lưu một bản ghi mới vào bảng `VerificationToken` với các thông tin:
      - `token`: `setupTokenDb` (UUID vừa tạo).
      - `code`: Mã bí mật 2FA (`secret.base32`) – **Lưu ý:** ở đây `code` lưu trữ mã bí mật, không phải mã OTP dùng một lần.
      - `email`: `req.user.email`.
      - `type`: `TypeOfVerificationCode.SETUP_2FA`.
      - `tokenType`: `TokenType.TWO_FACTOR_SECRET`.
      - `userId`: `req.user.userId`.
      - `expiresAt`: Thời gian hết hạn cho việc hoàn tất cài đặt (ví dụ: 10 phút, cấu hình từ `envConfig.TWO_FACTOR_SETUP_TOKEN_EXPIRES_IN`).
    - Nếu không lưu được, ném `OtpGenerationException` (hoặc một exception cụ thể hơn cho 2FA setup).
7.  **Audit Logging:** Ghi log thành công (`action: 'USER_2FA_SETUP_SUCCESS'`).
8.  **Trả về Response:** Trả về `{ message, otpauthUrl: secret.otpauthUrl, base32Secret: secret.base32, setupToken: setupTokenDb }`.

## 6. Tương tác FE/BE

1.  **FE:** Người dùng đã đăng nhập, vào trang cài đặt tài khoản, chọn "Cài đặt Xác thực Hai Yếu tố".
2.  **FE Call API:** `POST /auth/2fa/setup` (không cần body, `accessToken` được gửi qua header).
3.  **BE:** Xử lý như mục 5.
    - Kiểm tra user chưa bật 2FA.
    - Tạo mã bí mật 2FA, `otpauthUrl`.
    - Tạo và lưu `setupToken` (UUID) cùng với mã bí mật 2FA vào `VerificationToken`.
    - Trả về `{ otpauthUrl, base32Secret, setupToken }`.
4.  **FE:**
    - Nếu BE trả về **200 OK** với `otpauthUrl`, `base32Secret`, và `setupToken`:
      - Lưu `setupToken` (UUID) vào state.
      - Hiển thị mã QR (sử dụng `otpauthUrl`) cho người dùng quét bằng ứng dụng xác thực của họ (Google Authenticator, Authy,...).
      - Hiển thị `base32Secret` để người dùng có thể nhập thủ công nếu không quét được QR.
      - Hiển thị ô nhập mã TOTP 6 chữ số từ ứng dụng xác thực để xác minh.
      - (Xem tài liệu endpoint `POST /auth/2fa/verify` để tiếp tục luồng kích hoạt).
    - Nếu BE trả về **lỗi** (401, 409 đã bật 2FA, 500...): Hiển thị thông báo lỗi tương ứng.

## 7. Điểm nổi bật & Lưu ý

- **Mã Bí mật Chưa Kích hoạt:** Ở bước này, mã bí mật 2FA được tạo và liên kết với `setupToken`, nhưng nó CHƯA được lưu vào bản ghi `User` và 2FA CHƯA được kích hoạt cho người dùng. Việc kích hoạt chỉ xảy ra sau khi người dùng xác minh thành công mã TOTP đầu tiên ở endpoint `/auth/2fa/verify`.
- **`setupToken` là Quan trọng:** Token này liên kết yêu cầu cài đặt với việc xác minh mã TOTP, đảm bảo đúng người dùng đang thực hiện.
- **Lưu trữ Mã Bí mật Tạm thời:** Mã bí mật 2FA (`base32Secret`) được lưu trong trường `code` của `VerificationToken` với `type: SETUP_2FA` và `tokenType: TWO_FACTOR_SECRET`. Nó sẽ được lấy ra ở bước xác minh để kiểm tra mã TOTP.
- **Thời hạn cho `setupToken`:** Quá trình cài đặt (từ lúc nhận QR đến lúc xác minh) phải được hoàn thành trong một khoảng thời gian nhất định.
- **Audit Logging:** Ghi lại các bước khởi tạo cài đặt 2FA.
