# Endpoint: `POST /auth/send-otp` - Yêu cầu gửi mã OTP

## 1. Mô tả

Endpoint này được sử dụng để yêu cầu hệ thống gửi một mã OTP (One-Time Password) đến email của người dùng. Mã OTP này sau đó sẽ được dùng để xác thực trong các bước tiếp theo như xác minh email khi đăng ký, xác minh cho thao tác đặt lại mật khẩu, hoặc xác minh 2FA qua email (nếu được cấu hình).

Endpoint này có thể phục vụ nhiều mục đích (`type`): `REGISTER`, `FORGOT_PASSWORD`, `LOGIN_2FA` (nếu phương thức 2FA là OTP qua email).

## 2. Decorators

- `@IsPublic()`: Endpoint này công khai, không yêu cầu xác thực ban đầu.
- `@HttpCode(HttpStatus.OK)`: Trả về HTTP status 200 khi yêu cầu gửi OTP thành công (lưu ý: thành công ở đây nghĩa là yêu cầu được chấp nhận và xử lý, không nhất thiết là email đã được gửi đi ngay lập tức).
- `@ZodSerializerDto(SendOtpResDTO)`: Response trả về sẽ có dạng `SendOtpResDTO`.
- `@Throttle({ short: { limit: 3, ttl: 60000 }, long: { limit: 10, ttl: 3600000 } })`: Giới hạn tần suất truy cập để tránh spam email.

## 3. Request

- **Body:** `SendOtpBodyDTO`
  ```json
  {
    "email": "user@example.com",
    "type": "REGISTER" // Hoặc "FORGOT_PASSWORD", "LOGIN_2FA"
  }
  ```
  - `email` (string, required, email format): Email của người dùng để nhận mã OTP.
  - `type` (enum, required): Mục đích của OTP. Các giá trị hợp lệ được định nghĩa trong `TypeOfVerificationCode` enum (ví dụ: `REGISTER`, `FORGOT_PASSWORD`).
- **Headers (Tự động lấy bởi decorators):**
  - `User-Agent`: Lấy bởi `@UserAgent()` decorator.
  - `Client IP`: Lấy bởi `@Ip()` decorator.

## 4. Response

**4.1. Thành công:**

- **Status Code:** 200 OK
- \*\*Body (Serialized bởi `SendOtpResSchema`):
  ```json
  {
    "statusCode": 200,
    "message": "Auth.OTP.SentSuccess", // i18n key
    "data": {
      "message": "Auth.OTP.SentSuccess",
      "otpToken": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", // UUID của verification token (không phải mã OTP thực tế)
      "expiresAt": "YYYY-MM-DDTHH:mm:ss.sssZ"
    }
  }
  ```
  - `otpToken`: Đây là một UUID token được lưu trong DB để liên kết với mã OTP đã gửi. Nó sẽ được sử dụng trong bước xác thực OTP (`/auth/verify-code`). **Quan trọng:** Đây KHÔNG phải là mã OTP 6 chữ số mà người dùng nhập.
  - `expiresAt`: Thời gian OTP (và `otpToken` này) sẽ hết hạn.

**4.2. Lỗi:**

- **404 Not Found (`UserNotFoundException`):** Chỉ xảy ra nếu `type` là `FORGOT_PASSWORD` hoặc `LOGIN_2FA` và email không tồn tại trong hệ thống.
  ```json
  {
    "type": "https://api.shopsifu.live/errors/user-not-found",
    "title": "Not Found",
    "status": 404,
    "description": "Error.User.NotFound",
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid"
  }
  ```
- **409 Conflict (`UserAlreadyExistsException`):** Chỉ xảy ra nếu `type` là `REGISTER` và email đã tồn tại trong hệ thống.
  ```json
  {
    "type": "https://api.shopsifu.live/errors/user-already-exists",
    "title": "Conflict",
    "status": 409,
    "description": "Error.User.AlreadyExists",
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid",
    "errors": [
      {
        "field": "email",
        "description": "Error.User.AlreadyExists"
      }
    ]
  }
  ```
- **422 Unprocessable Entity (Validation Error):** Nếu request body không hợp lệ (ví dụ: email thiếu, `type` không hợp lệ).
- **429 Too Many Requests:** Nếu vượt quá giới hạn tần suất.
- **500 Internal Server Error (`OtpGenerationException`, `EmailSendingException`, `DeviceSetupFailedException`):**
  - Lỗi khi tạo mã OTP hoặc lưu `VerificationToken`.
  - Lỗi khi gửi email.
  - Lỗi khi xử lý thông tin thiết bị.
  ```json
  {
    "type": "https://api.shopsifu.live/errors/internal-server-error", // Hoặc một type cụ thể hơn
    "title": "Internal Server Error",
    "status": 500,
    "description": "Error.Auth.OTP.GenerationFailed", // Hoặc Error.Email.SendingFailed, Error.Auth.Device.SetupFailed
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid"
  }
  ```

## 5. Luồng Hoạt động (Backend - `AuthService.sendOtp`)

1.  **Validation:** Dữ liệu request (`email`, `type`) được validate bởi `SendOtpBodyDTO`.
2.  **Audit Logging:** Bắt đầu ghi log (`action: 'SEND_OTP_ATTEMPT'`, với `email` và `type`).
3.  **Prisma Transaction:** Các thao tác DB được thực hiện trong một transaction.
4.  **Kiểm tra User dựa trên `type`:**
    - Gọi `AuthRepository.findUserByEmail(email)`.
    - **Nếu `type` là `TypeOfVerificationCode.REGISTER`:**
      - Nếu user **đã tồn tại**: Ném `UserAlreadyExistsException`.
    - **Nếu `type` là `TypeOfVerificationCode.FORGOT_PASSWORD` hoặc `TypeOfVerificationCode.LOGIN_2FA`:**
      - Nếu user **không tồn tại**: Ném `UserNotFoundException`.
5.  **Xử lý Thiết bị:** Gọi `AuthRepository.findOrCreateDevice` với `userId` (nếu có, từ user tìm được ở bước 4, nếu không thì là `undefined`), `userAgent`, `ip` để lấy hoặc tạo `deviceId`. Nếu lỗi, ném `DeviceSetupFailedException`.
6.  **Tạo Mã OTP:** Gọi `SharedOtpService.generateOtpCode()` để tạo một mã OTP (ví dụ: 6 chữ số).
7.  **Tạo `VerificationToken` (UUID):** Tạo một `otpTokenDb` (UUID) mới.
8.  **Lưu `VerificationToken`:** Tạo và lưu một bản ghi mới vào bảng `VerificationToken` với các thông tin:
    - `token`: `otpTokenDb` (UUID vừa tạo).
    - `code`: Mã OTP 6 chữ số đã hash (sử dụng `HashingService.hash()`).
    - `email`: `body.email`.
    - `type`: `body.type`.
    - `tokenType`: `TokenType.OTP`.
    - `userId`: ID của user (nếu user được tìm thấy, ví dụ trong trường hợp `FORGOT_PASSWORD` hoặc `LOGIN_2FA`).
    - `deviceId`: `deviceId` từ bước 5.
    - `expiresAt`: Thời gian hết hạn (cấu hình từ `envConfig.OTP_TOKEN_EXPIRES_IN`).
    - Nếu không lưu được, ném `OtpGenerationException`.
9.  **Gửi Email:** Gọi `EmailService.sendOtpEmail` với `body.email`, mã OTP 6 chữ số (chưa hash), `body.type`, và `expiresAt`.
    - Nếu gửi email thất bại, ném `EmailSendingException`.
10. **Audit Logging:** Ghi log thành công (`action: 'SEND_OTP_SUCCESS'`).
11. **Trả về Response:** Trả về `{ message: "Auth.OTP.SentSuccess", otpToken: otpTokenDb, expiresAt }`.

## 6. Tương tác FE/BE

**6.1. Trường hợp Đăng ký (`type: "REGISTER"`):**

1.  **FE:** Người dùng nhập email vào form đăng ký, nhấn nút "Gửi mã OTP" / "Tiếp tục".
2.  **FE Call API:** `POST /auth/send-otp` với `email` và `type: "REGISTER"`.
3.  **BE:** Xử lý như mục 5.
    - Kiểm tra email chưa tồn tại.
    - Tạo OTP, lưu `VerificationToken` (UUID + OTP đã hash), gửi email chứa OTP.
    - Trả về `{ otpToken (UUID), expiresAt }`.
4.  **FE:**
    - Nếu BE trả về **200 OK** với `otpToken` (UUID):
      - Lưu `otpToken` (UUID) này và `email` vào state.
      - Hiển thị thông báo "Mã OTP đã được gửi đến email của bạn." và giao diện nhập mã OTP.
      - (Xem tài liệu endpoint `POST /auth/verify-code` để tiếp tục luồng).
    - Nếu BE trả về **lỗi** (409 email đã tồn tại, 422, 500...): Hiển thị thông báo lỗi tương ứng.

**6.2. Trường hợp Quên Mật khẩu (`type: "FORGOT_PASSWORD"`):**

1.  **FE:** Người dùng nhập email vào form quên mật khẩu, nhấn nút "Gửi mã OTP" / "Đặt lại mật khẩu".
2.  **FE Call API:** `POST /auth/send-otp` với `email` và `type: "FORGOT_PASSWORD"`.
3.  **BE:** Xử lý như mục 5.
    - Kiểm tra email đã tồn tại.
    - Tạo OTP, lưu `VerificationToken`, gửi email.
    - Trả về `{ otpToken (UUID), expiresAt }`.
4.  **FE:**
    - Nếu BE trả về **200 OK** với `otpToken` (UUID):
      - Lưu `otpToken` (UUID) và `email` vào state.
      - Hiển thị thông báo và giao diện nhập mã OTP.
      - (Xem tài liệu endpoint `POST /auth/verify-code` để tiếp tục luồng).
    - Nếu BE trả về **lỗi** (404 email không tồn tại, 422, 500...): Hiển thị thông báo lỗi.

## 7. Điểm nổi bật & Lưu ý

- **Mã OTP được Hash:** Mã OTP thực tế (6 chữ số) được hash trước khi lưu vào DB để tăng cường bảo mật. Chỉ mã đã hash mới được lưu.
- **`otpToken` (UUID) là Quan trọng:** `otpToken` trả về cho client không phải là mã OTP mà người dùng nhập. Nó là một định danh cho phiên xác thực OTP, dùng để liên kết yêu cầu gửi OTP và yêu cầu xác thực OTP.
- **Giới hạn Tần suất:** Rất quan trọng để ngăn chặn lạm dụng việc gửi email.
- **Xử lý Thiết bị:** Ghi nhận thông tin thiết bị ở bước này có thể hữu ích cho việc theo dõi và phân tích bảo mật sau này.
- **Đa mục đích:** Cùng một endpoint phục vụ nhiều luồng (đăng ký, quên mật khẩu) bằng cách sử dụng tham số `type`.
- **Audit Logging:** Ghi lại các nỗ lực yêu cầu OTP.
