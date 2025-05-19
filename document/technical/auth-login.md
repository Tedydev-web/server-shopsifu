# Endpoint: `POST /auth/login` - Đăng nhập tài khoản

## 1. Mô tả

Endpoint này cho phép người dùng đăng nhập vào hệ thống bằng email và mật khẩu. Nếu tài khoản người dùng đã kích hoạt Xác thực Hai Yếu tố (2FA), endpoint sẽ trả về một yêu cầu xác thực 2FA thay vì thông tin người dùng và token truy cập trực tiếp. Nếu không có 2FA, hoặc 2FA chưa được cấu hình đầy đủ, hệ thống sẽ trả về thông tin người dùng và thiết lập cookies cho `accessToken` và `refreshToken`.

## 2. Decorators

- `@IsPublic()`: Endpoint này công khai, không yêu cầu xác thực ban đầu.
- `@HttpCode(HttpStatus.OK)`: Luôn trả về HTTP status 200 cho cả trường hợp đăng nhập thành công và trường hợp yêu cầu 2FA.
- `@UseZodSchemas(...)`: Sử dụng decorator tùy chỉnh để serialize DTO trả về dựa trên điều kiện:
  - `UserProfileResSchema`: Nếu response chứa `userId` (đăng nhập thành công, không có 2FA hoặc 2FA đã verify xong ở bước khác).
  - `LoginSessionResSchema`: Nếu response chứa `loginSessionToken` (yêu cầu 2FA).
- `@Throttle({ short: { limit: 5, ttl: 60000 }, medium: { limit: 20, ttl: 300000 } })`: Giới hạn tần suất truy cập.

## 3. Request

- **Body:** `LoginBodyDTO`
  ```json
  {
    "email": "user@example.com",
    "password": "password123",
    "rememberMe": false
  }
  ```
  - `email` (string, required, email format): Email của người dùng.
  - `password` (string, required): Mật khẩu của người dùng.
  - `rememberMe` (boolean, optional, default: `false`): Nếu `true`, `refreshToken` sẽ có thời gian sống dài hơn (`REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN` thay vì `REFRESH_TOKEN_EXPIRES_IN`).
- **Headers (Tự động lấy bởi decorators):**
  - `User-Agent`: Lấy bởi `@UserAgent()` decorator.
  - `Client IP`: Lấy bởi `@Ip()` decorator.
- **Cookies (BE sẽ tự động ghi đè khi thành công):**
  - `access_token` (HttpOnly, Secure, SameSite=Lax, Path=/)
  - `refresh_token` (HttpOnly, Secure, SameSite=Lax, Path=/api/v1/auth)

## 4. Response

Có hai kịch bản response chính:

**4.1. Đăng nhập thành công (2FA không kích hoạt hoặc không được cấu hình đầy đủ):**

- **Status Code:** 200 OK
- **Body (Serialized bởi `UserProfileResSchema`):**
  ```json
  {
    "statusCode": 200,
    "message": "Global.Success", // Hoặc một message key cụ thể hơn
    "data": {
      "userId": 1,
      "email": "user@example.com",
      "name": "Shopsifu User",
      "role": "CLIENT"
    }
  }
  ```
- **Cookies được thiết lập:**
  - `access_token`: Chứa JWT Access Token.
  - `refresh_token`: Chứa JWT Refresh Token (UUID được lưu trong DB).

**4.2. Yêu cầu Xác thực Hai Yếu tố (2FA kích hoạt):**

- **Status Code:** 200 OK
- **Body (Serialized bởi `LoginSessionResSchema`):**
  ```json
  {
    "statusCode": 200,
    "message": "Auth.Login.2FARequired", // i18n key
    "data": {
      "message": "Auth.Login.2FARequired", // from LoginSessionResSchema
      "loginSessionToken": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", // UUID token
      "twoFactorMethod": "TOTP" // Hoặc "OTP", "RECOVERY"
    }
  }
  ```
- **Cookies:** Không có `access_token` hay `refresh_token` được thiết lập ở bước này.

**4.3. Lỗi:**

- **401 Unauthorized (Invalid Credentials):** Nếu email không tồn tại hoặc mật khẩu sai.
  - `InvalidLoginSessionException`: Thường khi email không tồn tại.
    ```json
    {
      "type": "https://api.shopsifu.live/errors/authentication-failure",
      "title": "Unauthorized",
      "status": 401,
      "description": "Error.Auth.Session.InvalidLogin",
      "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
      "requestId": "uuid"
    }
    ```
  - `InvalidPasswordException`: Khi mật khẩu sai.
    ```json
    {
      "type": "https://api.shopsifu.live/errors/authentication-failure",
      "title": "Unauthorized",
      "status": 401,
      "description": "Error.Auth.Password.Invalid",
      "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
      "requestId": "uuid",
      "errors": [
        {
          "field": "password",
          "description": "Error.Auth.Password.Invalid"
        }
      ]
    }
    ```
- **422 Unprocessable Entity (Validation Error):** Nếu request body không hợp lệ (ví dụ: email thiếu, password quá ngắn, theo `LoginBodySchema`).
  ```json
  {
    "type": "https://api.shopsifu.live/errors/validation-error",
    "title": "Unprocessable Entity",
    "status": 422,
    "description": "Error.Global.ValidationFailed",
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid",
    "errors": [
      {
        "field": "email", // hoặc "password"
        "description": "Error.Validation.email.invalid_string" // Key i18n từ Zod
      }
    ]
  }
  ```
- **500 Internal Server Error (`DeviceSetupFailedException`):** Nếu có lỗi trong quá trình tạo hoặc tìm thông tin thiết bị (`Device`).
  ```json
  {
    "type": "https://api.shopsifu.live/errors/device-setup-failed",
    "title": "Internal Server Error",
    "status": 500,
    "description": "Error.Auth.Device.SetupFailed",
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid"
  }
  ```
- **429 Too Many Requests:** Nếu vượt quá giới hạn tần suất.

## 5. Luồng Hoạt động (Backend - `AuthService.login`)

1.  **Validation:** Dữ liệu request (`email`, `password`, `rememberMe`) được validate bởi `LoginBodyDTO`.
2.  **Audit Logging:** Bắt đầu ghi log (`action: 'USER_LOGIN_ATTEMPT'`).
3.  **Prisma Transaction:** Các thao tác DB được thực hiện trong một transaction (`this.prismaService.$transaction`).
4.  **Tìm User:** Tìm người dùng trong bảng `User` bằng `email` (bao gồm cả `role`).
    - Nếu không tìm thấy, ném `InvalidLoginSessionException`.
5.  **Kiểm tra Mật khẩu:** So sánh `body.password` với `user.password` đã hash bằng `HashingService.compare()`.
    - Nếu không khớp, ném `InvalidPasswordException`.
6.  **Kiểm tra 2FA:**
    - **Nếu `user.twoFactorEnabled` là `true` VÀ `user.twoFactorSecret` VÀ `user.twoFactorMethod` đều có giá trị:**
      a. **Xử lý Thiết bị:** Gọi `AuthRepository.findOrCreateDevice` với `userId`, `userAgent`, `ip` để lấy hoặc tạo `deviceId`. Nếu lỗi, ném `DeviceSetupFailedException`.
      b. **Tạo `loginSessionToken`:** Tạo một `otpToken` (UUID) mới.
      c. **Lưu `loginSessionToken`:** Lưu token này vào bảng `VerificationToken` với các thông tin:
      _ `token`: UUID vừa tạo.
      _ `email`: `user.email`.
      _ `type`: `TypeOfVerificationCode.LOGIN_2FA`.
      _ `tokenType`: `TokenType.OTP`.
      _ `userId`: `user.id`.
      _ `deviceId`: `deviceId` từ bước (a).
      _ `metadata`: JSON string chứa `{ rememberMe: body.rememberMe }`.
      _ `expiresAt`: Thời gian hết hạn (cấu hình từ `envConfig.OTP_TOKEN_EXPIRES_IN`).
      d. **Trả Response 2FA:** Trả về `{ message: "Auth.Login.2FARequired", loginSessionToken: <UUID>, twoFactorMethod: user.twoFactorMethod }`.
      e. Ghi log thành công với ghi chú "2FA required".
    - **Nếu 2FA không được kích hoạt hoặc không được cấu hình đầy đủ:**
      a. **Xử lý Thiết bị:** Gọi `AuthRepository.findOrCreateDevice` với `userId`, `userAgent`, `ip` để lấy hoặc tạo `deviceId`. Nếu lỗi, ném `DeviceSetupFailedException`.
      b. **Tạo Tokens:** Gọi `AuthService.generateTokens` (phương thức nội bộ) với `userId`, `deviceId`, `roleId`, `roleName` và `body.rememberMe`.
      _ `generateTokens` sẽ:
      i. Tạo `accessToken` (JWT) bằng `TokenService.signAccessToken` (có `expiresIn` từ `envConfig.ACCESS_TOKEN_EXPIRES_IN`).
      ii. Tạo `refreshToken` (UUID).
      iii. Xác định thời gian hết hạn cho `refreshToken` (`REFRESH_TOKEN_COOKIE_MAX_AGE` hoặc `REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE` nếu `rememberMe` là true).
      iv. Lưu `refreshToken` (UUID) vào bảng `RefreshToken` cùng với `userId`, `deviceId`, `expiresAt` và `rememberMe`.
      v. Trả về `accessToken`, `refreshToken` (UUID), và `maxAgeForRefreshTokenCookie`.
      c. **Thiết lập Cookies:** Nếu có `res` object (response object của Express), gọi `TokenService.setTokenCookies` để thiết lập `access_token` và `refresh_token` vào HTTP response cookies.
      _ Cookie `access_token`: path `/`, maxAge từ `envConfig.ACCESS_TOKEN_COOKIE_MAX_AGE`. \* Cookie `refresh_token`: path `/api/v1/auth`, maxAge từ `maxAgeForRefreshTokenCookie`.
      d. **Trả Response Thành công:** Trả về thông tin người dùng: `{ userId, email, name, role: user.role.name }`.
      e. Ghi log thành công (`action: 'USER_LOGIN_SUCCESS'`).
7.  **Audit Logging:** Ghi log kết quả cuối cùng (thành công hoặc thất bại chi tiết).

## 6. Tương tác FE/BE

**6.1. Trường hợp không có 2FA (hoặc 2FA chưa được cấu hình):**

1.  **FE:** Người dùng nhập email, mật khẩu (và tùy chọn "Remember me") trên form đăng nhập. Nhấn nút "Đăng nhập".
2.  **FE Call API:** `POST /auth/login` với `email`, `password`, `rememberMe`.
3.  **BE:** Xử lý như mục 5 (trường hợp 2FA không kích hoạt).
    - Nếu thành công: Tạo tokens, lưu refresh token, thiết lập cookies, trả về thông tin user.
    - Nếu lỗi: Trả về lỗi tương ứng (sai thông tin, lỗi server,...).
4.  **FE:**
    - Nếu BE trả về **thông tin user (200 OK)**:
      - Đăng nhập thành công. FE lưu thông tin user vào state/context.
      - Chuyển hướng người dùng đến trang dashboard hoặc trang trước đó.
      - Cookies `access_token` và `refresh_token` đã được BE tự động thiết lập, FE không cần can thiệp trực tiếp vào việc set cookie này.
    - Nếu BE trả về **lỗi** (ví dụ: 401, 422, 500): Hiển thị thông báo lỗi cho người dùng.

**6.2. Trường hợp 2FA đã kích hoạt:**

1.  **FE:** Người dùng nhập email, mật khẩu (và tùy chọn "Remember me") trên form đăng nhập. Nhấn nút "Đăng nhập".
2.  **FE Call API:** `POST /auth/login` với `email`, `password`, `rememberMe`.
3.  **BE:** Xử lý như mục 5 (trường hợp 2FA kích hoạt).
    - Nếu email/password đúng và 2FA kích hoạt: Tạo `loginSessionToken`, lưu vào DB, trả về `{ loginSessionToken, twoFactorMethod }`.
    - Nếu email/password sai: Trả về lỗi 401.
4.  **FE:**
    - Nếu BE trả về **`loginSessionToken` và `twoFactorMethod` (200 OK)**:
      - FE hiểu rằng cần bước xác thực 2FA.
      - Lưu `loginSessionToken` và `twoFactorMethod` vào state.
      - Hiển thị giao diện nhập mã 2FA (ví dụ: ô nhập mã TOTP nếu `twoFactorMethod` là `"TOTP"`, hoặc các tùy chọn khác như gửi OTP qua email nếu hỗ trợ).
      - (Xem tài liệu endpoint `POST /auth/2fa/verify` để tiếp tục luồng).
    - Nếu BE trả về **lỗi** (ví dụ: 401): Hiển thị thông báo lỗi (sai email/mật khẩu).

## 7. Điểm nổi bật & Lưu ý

- **Bảo mật Cookies:** `accessToken` và `refreshToken` được thiết lập là `HttpOnly`, giúp giảm nguy cơ bị đánh cắp qua XSS. `Secure` flag được dùng trong môi trường production.
- **Luồng 2FA tách biệt:** Việc tách luồng 2FA giúp mã nguồn rõ ràng hơn. `loginSessionToken` là một token trung gian quan trọng, có thời hạn ngắn, liên kết yêu cầu đăng nhập ban đầu với yêu cầu xác thực 2FA.
- **Xử lý Thiết bị (`Device`):** Mỗi lần đăng nhập hoặc yêu cầu 2FA, thông tin thiết bị (User Agent, IP) được ghi nhận và có thể được dùng để tăng cường bảo mật (ví dụ: phát hiện đăng nhập từ thiết bị lạ). `deviceId` được gắn vào `accessToken` và `refreshToken`.
- **Remember Me:** Ảnh hưởng đến thời gian sống của `refreshToken` và cookie tương ứng.
- **Serialization động:** `@UseZodSchemas` cho phép trả về các cấu trúc DTO khác nhau tùy thuộc vào kết quả của logic nghiệp vụ (đăng nhập thành công ngay hay cần 2FA).
- **Audit Logging:** Mọi nỗ lực đăng nhập, dù thành công hay thất bại, đều được ghi log chi tiết.

</rewritten_file>
