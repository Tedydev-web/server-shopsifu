# Tài liệu Kỹ thuật Module Xác thực (Auth Module)

## Mục lục

1.  [Giới thiệu](#giới-thiệu)
2.  [Luồng Đăng ký Người dùng](#luồng-đăng-ký-người-dùng)
    - [2.1. `POST /auth/send-otp` - Yêu cầu gửi mã OTP](#21-post-authsend-otp---yêu-cầu-gửi-mã-otp)
    - [2.2. `POST /auth/verify-code` - Xác thực mã OTP](#22-post-authverify-code---xác-thực-mã-otp)
    - [2.3. `POST /auth/register` - Đăng ký tài khoản](#23-post-authregister---đăng-ký-tài-khoản)
3.  [Luồng Đăng nhập](#luồng-đăng-nhập)
    - [3.1. `POST /auth/login` - Đăng nhập tài khoản](#31-post-authlogin---đăng-nhập-tài-khoản)
4.  [Luồng Làm mới Token](#luồng-làm-mới-token)
    - [4.1. `POST /auth/refresh-token` - Làm mới Access Token](#41-post-authrefresh-token---làm-mới-access-token)
5.  [Đăng xuất](#đăng-xuất)
    - [5.1. `POST /auth/logout` - Đăng xuất tài khoản](#51-post-authlogout---đăng-xuất-tài-khoản)
6.  [Luồng Quên mật khẩu](#luồng-quên-mật-khẩu)
    - [6.1. `POST /auth/send-otp` (type: FORGOT_PASSWORD)](#61-post-authsend-otp-type-forgot_password)
    - [6.2. `POST /auth/verify-code` (type: FORGOT_PASSWORD)](#62-post-authverify-code-type-forgot_password)
    - [6.3. `POST /auth/reset-password` - Đặt lại mật khẩu](#63-post-authreset-password---đặt-lại-mật-khẩu)
7.  [Xác thực với Google](#xác-thực-với-google)
    - [7.1. `GET /auth/google-link` - Lấy URL xác thực Google](#71-get-authgoogle-link---lấy-url-xác-thực-google)
    - [7.2. `POST /auth/google/callback` - Xử lý callback từ Google](#72-post-authgooglecallback---xử-lý-callback-từ-google)
8.  [Quản lý Xác thực Hai Yếu tố (2FA)](#quản-lý-xác-thực-hai-yếu-tố-2fa)
    - [8.1. `POST /auth/2fa/setup` - Yêu cầu thiết lập 2FA](#81-post-auth2fasetup---yêu-cầu-thiết-lập-2fa)
    - [8.2. `POST /auth/2fa/confirm-setup` - Xác nhận thiết lập 2FA](#82-post-auth2faconfirm-setup---xác-nhận-thiết-lập-2fa)
    - [8.3. `POST /auth/2fa/disable` - Vô hiệu hóa 2FA](#83-post-auth2fadisable---vô-hiệu-hóa-2fa)
    - [8.4. `POST /auth/2fa/verify` - Xác thực mã 2FA (khi đăng nhập)](#84-post-auth2faverify---xác-thực-mã-2fa-khi-đăng-nhập)

---

## Giới thiệu

Module `Auth` chịu trách nhiệm cho tất cả các quy trình liên quan đến xác thực và quản lý phiên người dùng, bao gồm đăng ký, đăng nhập, đăng xuất, làm mới token, quên mật khẩu và xác thực hai yếu tố (2FA).

---

## Luồng Đăng ký Người dùng

Luồng đăng ký người dùng mới bao gồm 3 bước chính: yêu cầu OTP, xác thực OTP và hoàn tất đăng ký.

### 2.1. `POST /auth/send-otp` - Yêu cầu gửi mã OTP

- **Mô tả:** Endpoint này được sử dụng để yêu cầu hệ thống gửi một mã OTP (One-Time Password) gồm 6 chữ số đến địa chỉ email của người dùng. Mã OTP này sẽ được sử dụng ở bước tiếp theo để xác thực email.
- **Decorators:**
  - `@IsPublic()`: Endpoint này công khai, không yêu cầu xác thực.
  - `@ZodSerializerDto(MessageResDTO)`: Định dạng response thành công.
  - `@Throttle({ short: { limit: 3, ttl: 60000 }, long: { limit: 10, ttl: 3600000 } })`: Giới hạn tần suất yêu cầu.
- **Request:**
  - **Body:** `SendOTPBodyDTO`
    ```json
    {
      "email": "user@example.com",
      "type": "REGISTER"
    }
    ```
    - `email` (string, required, email format): Địa chỉ email để nhận OTP.
    - `type` (string, required, enum): Loại OTP yêu cầu. Đối với đăng ký, giá trị là `"REGISTER"`. Các giá trị khác có thể là `"FORGOT_PASSWORD"`, `"LOGIN_2FA"`, `"DISABLE_2FA"`, `"SETUP_2FA"`.
- **Response:**
  - **Thành công (200 OK):**
    ```json
    {
      "statusCode": 200,
      "message": "Auth.Otp.SentSuccessfully", // i18n key
      "data": {
        "message": "Auth.Otp.SentSuccessfully" // Actual data from MessageResDTO
      }
    }
    ```
  - **Lỗi:**
    - **409 Conflict (Email Already Exists):** Nếu `type` là `"REGISTER"` và email đã tồn tại.
      ```json
      {
        "type": "https://api.shopsifu.live/errors/validation-error", // Or specific conflict type
        "title": "Conflict",
        "status": 409,
        "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "requestId": "uuid",
        "description": "Error.Auth.Email.AlreadyExists", // i18n key
        "errors": [
          {
            "field": "email",
            "description": "Error.Auth.Email.AlreadyExists" // i18n key
          }
        ]
      }
      ```
    - **500 Internal Server Error (Failed to Send OTP):** Nếu có lỗi khi gửi email.
      ```json
      {
        "type": "https://api.shopsifu.live/errors/otp-service-error",
        "title": "Internal Server Error",
        "status": 500,
        "description": "Error.Auth.Otp.FailedToSend", // i18n key
        "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "requestId": "uuid"
      }
      ```
    - **429 Too Many Requests:** Nếu vượt quá giới hạn tần suất.
- **Luồng Hoạt động (Backend):**
  1.  **Validation:** Dữ liệu request body được validate bởi `SendOTPBodyDTO`.
  2.  **Kiểm tra Email:**
      - Nếu `type` là `"REGISTER"`, `AuthService` (`sendOTP` method) kiểm tra xem email đã tồn tại trong `User` table chưa (thông qua `SharedUserRepository`). Nếu đã tồn tại, ném `EmailAlreadyExistsException`.
  3.  **Xóa OTP cũ:** Xóa các bản ghi `VerificationCode` cũ cho `email` và `type` này (thông qua `AuthRepository.deleteVerificationCodesByEmailAndType`).
  4.  **Tạo OTP:** Tạo một mã OTP 6 chữ số ngẫu nhiên (`generateOTP()` helper).
  5.  **Lưu OTP:** Lưu mã OTP mới vào `VerificationCode` table cùng với `email`, `type`, và `expiresAt` (thời gian hết hạn được cấu hình, ví dụ: 15 phút, từ `envConfig.OTP_TOKEN_EXPIRES_IN`) (thông qua `AuthRepository.createVerificationCode`).
  6.  **Gửi Email:** Gửi email chứa mã OTP đến địa chỉ email người dùng (thông qua `EmailService.sendOTP`). Nếu gửi thất bại, ném `FailedToSendOTPException`.
  7.  **Trả về Response:** Trả về thông báo thành công.
- **Tương tác FE/BE:**
  1.  **FE:** Người dùng nhập email trên form đăng ký và nhấn nút "Gửi mã". FE gọi API `POST /auth/send-otp` với `email` và `type: "REGISTER"`.
  2.  **BE:** Xử lý như mô tả ở trên.
  3.  **FE:**
      - Nếu thành công: Hiển thị thông báo "Đã gửi mã OTP. Vui lòng kiểm tra email." và cho phép người dùng nhập mã OTP.
      - Nếu lỗi (ví dụ: email đã tồn tại): Hiển thị thông báo lỗi tương ứng.

### 2.2. `POST /auth/verify-code` - Xác thực mã OTP

- **Mô tả:** Sau khi người dùng nhận được mã OTP 6 chữ số qua email, họ sử dụng endpoint này để xác thực mã đó. Nếu thành công, hệ thống sẽ trả về một `otpToken` (UUID) - đây là một token trung gian, có thời hạn, dùng cho bước đăng ký cuối cùng.
- **Decorators:**
  - `@IsPublic()`
  - `@ZodSerializerDto(VerifyCodeResDTO)`
  - `@Throttle({ short: { limit: 5, ttl: 10000 }, long: { limit: 30, ttl: 60000 } })`
- **Request:**
  - **Body:** `VerifyCodeBodyDTO`
    ```json
    {
      "email": "user@example.com",
      "code": "123456",
      "type": "REGISTER"
    }
    ```
    - `email` (string, required, email format)
    - `code` (string, required, length 6): Mã OTP 6 chữ số người dùng nhập.
    - `type` (string, required, enum): Loại mã đang xác thực, ví dụ `"REGISTER"`.
  - **Headers (Tự động lấy bởi decorators):**
    - `User-Agent`: Lấy bởi `@UserAgent()` decorator.
    - `Client IP`: Lấy bởi `@Ip()` decorator.
- **Response:**
  - **Thành công (200 OK):**
    ```json
    {
      "statusCode": 200,
      "message": "Global.Success", // Hoặc một message key cụ thể hơn nếu có
      "data": {
        "otpToken": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" // UUID token
      }
    }
    ```
  - **Lỗi:**
    - **422 Unprocessable Entity (Invalid OTP / OTP Expired):**
      ```json
      // Ví dụ: Mã OTP không hợp lệ
      {
        "type": "https://api.shopsifu.live/errors/validation-error",
        "title": "Unprocessable Entity",
        "status": 422,
        "description": "Error.Auth.Otp.Invalid", // i18n key
        "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "requestId": "uuid",
        "errors": [
          {
            "field": "code", // path của lỗi
            "description": "Error.Auth.Otp.Invalid" // i18n key
          }
        ]
      }
      ```
    - **429 Too Many Requests.**
    - **500 Internal Server Error (Device Setup Failed):** Nếu có lỗi khi tạo/tìm device.
      ```json
      {
        "type": "https://api.shopsifu.live/errors/device-setup-failed",
        "title": "Internal Server Error",
        "status": 500,
        "description": "Error.Auth.Device.SetupFailed", // i18n key
        "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "requestId": "uuid"
      }
      ```
- **Luồng Hoạt động (Backend):**
  1.  **Validation:** Request body được validate bởi `VerifyCodeBodyDTO`.
  2.  **Audit Logging:** Bắt đầu ghi log (`AuthService.verifyCode`).
  3.  **Prisma Transaction:** Các thao tác DB được thực hiện trong một transaction.
  4.  **Xác thực OTP 6 chữ số:**
      - `AuthService` gọi `validateVerificationCode` (phương thức nội bộ) để kiểm tra `email`, `code` (6 chữ số), `type` với bảng `VerificationCode`.
      - Nếu không tìm thấy hoặc mã hết hạn, ném `InvalidOTPException` hoặc `OTPExpiredException`.
  5.  **Xóa OTP Token (UUID) cũ:** Xóa các `VerificationToken` (token UUID) cũ có cùng `email`, `type`, và `tokenType: TokenType.OTP` (thông qua `AuthRepository.deleteVerificationTokenByEmailAndType`). Điều này đảm bảo mỗi lần xác thực code 6 số thành công sẽ chỉ có một UUID token mới hợp lệ.
  6.  **Xử lý Thiết bị (Device):**
      - Nếu `type` không phải là `REGISTER` (ví dụ: `LOGIN_2FA`, `FORGOT_PASSWORD`), tìm `userId` dựa trên `email`.
      - Nếu `userId` được tìm thấy (hoặc nếu logic cho phép tạo device ngay cả khi chưa có user cho một số flow nhất định), gọi `AuthRepository.findOrCreateDevice` để tìm hoặc tạo một bản ghi `Device` mới dựa trên `userId`, `userAgent` và `ip`. `deviceId` sẽ được lưu lại.
      - Lỗi ở bước này có thể ném `DeviceSetupFailedException`.
  7.  **Tạo `otpToken` (UUID):** Tạo một UUID mới (`uuidv4()`).
  8.  **Lưu `otpToken` (UUID):**
      - Lưu UUID này vào bảng `VerificationToken` với các thông tin: `token` (UUID), `email`, `type`, `tokenType: TokenType.OTP`, `userId` (nếu có), `deviceId` (nếu có), và `expiresAt` (cấu hình từ `envConfig.OTP_TOKEN_EXPIRES_IN`, ví dụ 15 phút). Thực hiện qua `AuthRepository.createVerificationToken`.
  9.  **Xóa OTP 6 chữ số đã dùng:** Xóa bản ghi mã OTP 6 chữ số khỏi bảng `VerificationCode` (thông qua `AuthRepository.deleteVerificationCode`).
  10. **Audit Logging:** Ghi log thành công.
  11. **Trả về Response:** Trả về `{ otpToken: <UUID> }`.
- **Tương tác FE/BE:**
  1.  **FE:** Sau khi người dùng nhập mã OTP 6 chữ số đã nhận, FE gọi API `POST /auth/verify-code` với `email`, `code` (6 chữ số) và `type: "REGISTER"`.
  2.  **BE:** Xử lý như mô tả ở trên.
  3.  **FE:**
      - Nếu thành công: Nhận được `otpToken` (UUID). Lưu trữ token này (ví dụ: trong state) để sử dụng cho API đăng ký cuối cùng. Cho phép người dùng nhập các thông tin còn lại của form đăng ký (tên, mật khẩu,...).
      - Nếu lỗi (OTP sai, hết hạn,...): Hiển thị thông báo lỗi tương ứng.

### 2.3. `POST /auth/register` - Đăng ký tài khoản

- **Mô tả:** Đây là bước cuối cùng của luồng đăng ký. Người dùng gửi tất cả thông tin cá nhân cần thiết cùng với `otpToken` (UUID) đã nhận được từ bước `verify-code`.
- **Decorators:**
  - `@IsPublic()`
  - `@ZodSerializerDto(RegisterResDTO)`: `RegisterResDTO` dựa trên `RegisterResSchema` (thông tin user không bao gồm password, totpSecret).
  - `@Throttle({ short: { limit: 5, ttl: 10000 }, long: { limit: 20, ttl: 60000 } })`
- **Request:**
  - **Body:** `RegisterBodyDTO`
    ```json
    {
      "email": "user@example.com",
      "password": "password123",
      "confirmPassword": "password123",
      "name": "Test User",
      "phoneNumber": "0123456789",
      "otpToken": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" // UUID từ /auth/verify-code
    }
    ```
    - `otpToken` (string, required, uuid format): Token UUID nhận được từ `POST /auth/verify-code`.
  - **Headers (Tự động lấy bởi decorators):**
    - `User-Agent`: Lấy bởi `@UserAgent()` decorator.
    - `Client IP`: Lấy bởi `@Ip()` decorator.
- **Response:**
  - **Thành công (201 Created):** (Hoặc 200 OK tùy cấu hình `HttpCode`)
    ```json
    {
      "statusCode": 201, // Hoặc 200
      "message": "Global.Success", // Hoặc một message key cụ thể hơn
      "data": {
        // Dữ liệu User theo RegisterResSchema
        "id": 1,
        "email": "user@example.com",
        "name": "Test User",
        "phoneNumber": "0123456789",
        "avatar": null,
        "status": "INACTIVE", // Hoặc ACTIVE tùy logic sau đăng ký
        "roleId": 2, // ID của role "Client"
        "createdById": null,
        "updatedById": null,
        "deletedAt": null,
        "createdAt": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "updatedAt": "YYYY-MM-DDTHH:mm:ss.sssZ"
      }
    }
    ```
  - **Lỗi:**
    - **422 Unprocessable Entity (Invalid/Expired otpToken, Password mismatch, Email already exists):**
      ```json
      // Ví dụ: otpToken không hợp lệ
      {
        "type": "https://api.shopsifu.live/errors/validation-error",
        "title": "Unprocessable Entity",
        "status": 422,
        "description": "Error.Auth.OtpToken.Invalid", // Hoặc "Error.Auth.OtpToken.Expired"
        "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "requestId": "uuid",
        "errors": [
          {
            "field": "otpToken",
            "description": "Error.Auth.OtpToken.Invalid"
          }
        ]
      }
      // Ví dụ: Email đã tồn tại (nếu check lại ở bước này)
      {
        "type": "https://api.shopsifu.live/errors/conflict", // Hoặc validation-error
        "title": "Conflict", // Hoặc Unprocessable Entity
        "status": 409, // Hoặc 422
        "description": "Error.Auth.Email.AlreadyExists",
        "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "requestId": "uuid",
        "errors": [
          {
            "field": "email",
            "description": "Error.Auth.Email.AlreadyExists"
          }
        ]
      }
      // Ví dụ: Mật khẩu không khớp (validation của DTO)
      {
        "type": "https://api.shopsifu.live/errors/validation-error",
        "title": "Unprocessable Entity",
        "status": 422,
        "description": "Error.Global.ValidationFailed",
        "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "requestId": "uuid",
        "errors": [
          {
            "field": "confirmPassword",
            "description": "Error.Validation.confirmPassword.custom" // Key i18n cho lỗi custom refine
          }
        ]
      }
      ```
    - **401 Unauthorized (Device Mismatch):** Nếu `otpToken` có `deviceId` và `userAgent`/`ip` không khớp.
      ```json
      {
        "type": "https://api.shopsifu.live/errors/authentication-failure", // or specific device error type
        "title": "Unauthorized",
        "status": 401,
        "description": "Error.Auth.Device.Mismatch",
        "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
        "requestId": "uuid"
      }
      ```
    - **429 Too Many Requests.**
- **Luồng Hoạt động (Backend):**
  1.  **Validation:** Request body được validate bởi `RegisterBodyDTO` (bao gồm check `password` và `confirmPassword` khớp nhau).
  2.  **Audit Logging:** Bắt đầu ghi log (`AuthService.register`).
  3.  **Prisma Transaction:** Các thao tác DB được thực hiện trong một transaction.
  4.  **Xác thực `otpToken` (UUID):**
      - `AuthService` gọi `validateVerificationToken` (phương thức nội bộ) để kiểm tra `otpToken` (UUID) với các thông tin `email`, `type: TypeOfVerificationCode.REGISTER`, `tokenType: TokenType.OTP` trong bảng `VerificationToken`.
      - Nếu token không hợp lệ, không tìm thấy, hoặc đã hết hạn, ném `InvalidOTPTokenException` hoặc `OTPTokenExpiredException`.
  5.  **Kiểm tra Thiết bị (Device Validation):**
      - Nếu `otpToken` (UUID) có chứa `deviceId` (tức là device đã được ghi nhận ở bước `verify-code`) và request hiện tại có `userAgent`, `ip`, thì `AuthService` gọi `AuthRepository.validateDevice` để xác thực.
      - `validateDevice` kiểm tra xem device có `isActive`, `userAgent` có khớp không. Nó cũng cập nhật `lastActive` và `ip` của device.
      - Nếu device không hợp lệ (không active, userAgent không khớp), ném `DeviceMismatchException`.
  6.  **Lấy Role ID:** Lấy `roleId` cho "Client" từ `RolesService.getClientRoleId()`.
  7.  **Hash Mật khẩu:** Hash `body.password` bằng `HashingService.hash()`.
  8.  **Kiểm tra Email Tồn tại (Lần cuối):** `AuthService` thực hiện kiểm tra lại (ví dụ `tx.user.findUnique`) trước khi tạo user để tránh trường hợp race condition, mặc dù `send-otp` đã check.
  9.  **Tạo Người dùng:** Tạo bản ghi mới trong bảng `User` với `email`, `name`, `hashedPassword`, `phoneNumber`, `roleId` (thông qua `AuthRepository.createUser`).
      - Nếu có lỗi unique constraint (ví dụ: email đã tồn tại do race condition), Prisma sẽ ném lỗi. `AuthService` bắt lỗi này và ném lại `EmailAlreadyExistsException`.
  10. **Xóa `otpToken` (UUID) đã dùng:** Xóa bản ghi `otpToken` (UUID) khỏi bảng `VerificationToken` (thông qua `AuthRepository.deleteVerificationToken`).
  11. **Audit Logging:** Ghi log thành công.
  12. **Trả về Response:** Trả về thông tin user vừa tạo (đã được serialize bởi `RegisterResDTO`).
- **Tương tác FE/BE:**
  1.  **FE:** Sau khi xác thực OTP 6 chữ số thành công (bước `verify-code`) và nhận được `otpToken` (UUID), FE cho phép người dùng nhập các thông tin còn lại (tên, mật khẩu,...) và submit form đăng ký. FE gọi API `POST /auth/register` với đầy đủ thông tin, bao gồm cả `otpToken` (UUID).
  2.  **BE:** Xử lý như mô tả ở trên.
  3.  **FE:**
      - Nếu thành công: Hiển thị thông báo "Đăng ký thành công!". Có thể tự động chuyển hướng người dùng sang trang đăng nhập hoặc trang chào mừng.
      - Nếu lỗi: Hiển thị thông báo lỗi tương ứng (OTP token không hợp lệ/hết hạn, email đã tồn tại, mật khẩu không khớp, device không khớp...).

---

<!-- Tiếp theo sẽ là các luồng khác như Đăng nhập, Quên mật khẩu, etc. -->
