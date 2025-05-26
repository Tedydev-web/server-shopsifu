# Tài liệu API Module Authentication (`@auth`)

Đây là tài liệu chi tiết về các API endpoint trong module `auth` của ứng dụng Shopsifu.

## Mục lục

1.  [Tổng quan](#tổng-quan)
2.  [Các Thành phần Chính](#các-thành-phần-chính)
3.  [Luồng Xác thực Chung](#luồng-xác-thực-chung)
4.  [Chi tiết Endpoints](#chi-tiết-endpoints)
    - [Đăng ký](#đăng-ký)
    - [Gửi OTP](#gửi-otp)
    - [Xác minh Mã (Chung)](#xác-minh-mã-chung)
    - [Đăng nhập](#đăng-nhập)
    - [Làm mới Token](#làm-mới-token)
    - [Đăng xuất](#đăng-xuất)
    - [Đăng nhập bằng Google](#đăng-nhập-bằng-google)
    - [Đặt lại Mật khẩu](#đặt-lại-mật-khẩu)
    - [Quản lý Xác thực Hai Yếu tố (2FA)](#quản-lý-xác-thực-hai-yếu-tố-2fa)
    - [Quản lý Phiên & Thiết bị](#quản-lý-phiên--thiết-bị)
5.  [Rủi ro và Cải tiến](#rủi-ro-và-cải-tiến)

## 1. Tổng quan

Module `@auth` chịu trách nhiệm cho tất cả các quy trình liên quan đến xác thực người dùng, quản lý phiên, bảo mật tài khoản (2FA, quản lý thiết bị), và tích hợp đăng nhập qua các nhà cung cấp bên thứ ba (Google).

## 2. Các Thành phần Chính

- **`AuthController`**: Tiếp nhận request, gọi các service tương ứng.
- **`AuthService`**: Điều phối chính các logic nghiệp vụ, gọi các service con.
- **Service con chuyên biệt**:
  - `AuthenticationService`: Xử lý đăng ký, đăng nhập, đăng xuất cơ bản.
  - `OtpAuthService`: Xử lý gửi và xác minh OTP (không bao gồm 2FA).
  - `PasswordAuthService`: Xử lý đặt lại/thay đổi mật khẩu.
  - `TwoFactorAuthService`: Xử lý logic 2FA (setup, confirm, disable, verify).
  - `SessionManagementService`: Quản lý phiên hoạt động, thiết bị được quản lý.
  - `GoogleService`: Xử lý đăng nhập qua Google.
- **Provider Service**:
  - `TokenService`: Tạo, xác minh, quản lý vòng đời của access token và refresh token (JTI).
  - `DeviceService`: Tìm, tạo, xác thực, quản lý thiết bị (fingerprint, trust status).
  - `OtpService`: Logic cốt lõi của việc tạo, xác minh mã OTP/token (lưu trữ trong DB).
  - `EmailService`: Gửi email (OTP, thông báo bảo mật).
  - `TwoFactorService`: Logic cốt lõi của TOTP (tạo secret, verify code) và mã khôi phục.
- **Repository**: `AuthRepository`, `SharedUserRepository` tương tác với Prisma.
- **Guards**: `AccessTokenGuard`, `RolesGuard`, `AuthenticationGuard` (guard chung).
- **Interceptor**: `TokenRefreshInterceptor` (có thể không còn dùng nếu client chủ động refresh), `AuditLogInterceptor`.
- **Khác**: `HashingService`, `I18nService`, `RedisService`, `AuditLogService`, `GeolocationService`.

## 3. Luồng Xác thực Chung

1.  **Đăng ký/Đăng nhập**: Người dùng cung cấp thông tin.
2.  **Xác thực**: Hệ thống kiểm tra thông tin.
3.  **Tạo Session & Token**: Nếu thành công, một session được tạo trên Redis, access token (ngắn hạn) và refresh token (dài hạn, lưu JTI) được tạo và gửi về client (access token trong response body, refresh token trong HTTPOnly cookie).
4.  **Truy cập API**: Client gửi access token trong header `Authorization: Bearer <token>`.
5.  **`AccessTokenGuard`**: Kiểm tra tính hợp lệ của access token, thông tin session trên Redis.
6.  **Làm mới Token**: Khi access token hết hạn, client dùng refresh token để yêu cầu access token mới.
7.  **Quản lý thiết bị**: Dấu vân tay thiết bị (user agent + IP) được sử dụng để nhận diện thiết bị. Thiết bị có thể được "tin cậy".
8.  **2FA**: Nếu được bật, người dùng cần cung cấp mã TOTP/OTP hoặc mã khôi phục sau khi đăng nhập thành công bằng mật khẩu.

## 4. Chi tiết Endpoints

---

### Đăng ký

- **Endpoint**: `POST /auth/register`
- **Mục đích**: Đăng ký tài khoản người dùng mới.
- **Public**: Có (`@IsPublic()`)
- **Request Headers**:
  - `User-Agent`: (Tự động lấy bởi `@UserAgent()`)
- **Request Body**: `RegisterBodyDTO`
  ```json
  {
    "email": "user@example.com",
    "password": "password123",
    "confirmPassword": "password123",
    "name": "User Name",
    "phoneNumber": "0123456789",
    "otpToken": "jwt_otp_token_from_verify_code_step" // Token nhận được sau khi xác minh OTP loại REGISTER
  }
  ```
- **Authorization**: Không cần.
- **Luồng xử lý**:
  1.  `AuthController.register` nhận request.
  2.  Gọi `AuthService.register` (thực chất là `AuthenticationService.register`).
  3.  `OtpService.validateVerificationToken`: Xác thực `otpToken` (loại `REGISTER`, email phải khớp).
  4.  Kiểm tra email đã tồn tại chưa (`SharedUserRepository.findUnique`).
  5.  Hash mật khẩu (`HashingService.hash`).
  6.  Lấy `roleId` mặc định (`RolesService.getClientRoleId`).
  7.  Tạo user mới trong DB (`AuthRepository.createUser`).
  8.  Xóa `otpToken` đã sử dụng (`OtpService.deleteOtpToken`).
  9.  Ghi Audit Log.
  10. Trả về thông tin user đã lược bỏ (không có password, 2FA secret).
- **Response Body (Success - 201 Created)**: `RegisterResDTO` (thông tin user)
  ```json
  {
    "id": 1,
    "email": "user@example.com",
    "name": "User Name",
    "phoneNumber": "0123456789",
    "avatar": null,
    "status": "ACTIVE",
    "roleId": 2,
    "twoFactorEnabled": false,
    "twoFactorMethod": null,
    "twoFactorVerifiedAt": null,
    "deletedAt": null,
    "createdAt": "2023-10-27T10:00:00.000Z",
    "updatedAt": "2023-10-27T10:00:00.000Z"
  }
  ```
- **Response Body (Error)**: Cấu trúc lỗi chuẩn (xem `AllExceptionsFilter`).
  - `422 Unprocessable Entity`: Nếu `otpToken` không hợp lệ/hết hạn, email/password không đúng định dạng, password không khớp.
  - `409 Conflict`: Nếu email đã tồn tại.
- **Rủi ro/Cải tiến**:
  - Trạng thái `INACTIVE` sau đăng ký có thể yêu cầu một bước kích hoạt email khác (nếu `otpToken` chỉ để xác minh email trước khi đăng ký). Nếu `otpToken` đã là kích hoạt thì nên là `ACTIVE`. Cần làm rõ logic này.
  - Xem xét việc gửi email chào mừng sau khi đăng ký thành công.

---

### Gửi OTP

- **Endpoint**: `POST /auth/send-otp`
- **Mục đích**: Yêu cầu hệ thống gửi mã OTP đến email người dùng cho các mục đích khác nhau (đăng ký, đặt lại mật khẩu, đăng nhập thiết bị lạ).
- **Public**: Có (`@IsPublic()`)
- **Request Body**: `SendOTPBodyDTO`
  ```json
  {
    "email": "user@example.com",
    "type": "REGISTER" // hoặc "RESET_PASSWORD", "LOGIN_UNTRUSTED_DEVICE_OTP"
  }
  ```
- **Authorization**: Không cần.
- **Luồng xử lý**:
  1.  `AuthController.sendOTP` nhận request.
  2.  Gọi `AuthService.sendOTP` (thực chất là `OtpAuthService.sendOTP`).
  3.  `OtpService.sendOTP` được gọi:
      - Kiểm tra email có tồn tại không (tùy theo `type` - ví dụ `RESET_PASSWORD` cần email tồn tại, `REGISTER` thì không).
      - Tạo mã OTP (6 chữ số).
      - Lưu `VerificationCode` vào DB (email, code, type, expiresAt).
      - Gửi email chứa mã OTP (`EmailService.sendOTP`).
  4.  Ghi Audit Log.
- **Response Body (Success - 201 Created)**: `MessageResDTO`
  ```json
  {
    "message": "OTP has been sent successfully." // (Key i18n: error.Auth.Otp.SentSuccessfully)
  }
  ```
- **Response Body (Error)**:
  - `404 Not Found`: Nếu `type` là `RESET_PASSWORD` và email không tồn tại.
  - `500 Internal Server Error`: Nếu gửi email thất bại.
- **Rủi ro/Cải tiến**:
  - Rate limiting mạnh mẽ để chống spam OTP.
  - OTP nên có thời gian sống ngắn.

---

### Xác minh Mã (Chung)

- **Endpoint**: `POST /auth/verify-code`
- **Mục đích**: Xác minh mã OTP đã được gửi trước đó và nếu thành công, trả về một `otpToken` (JWT ngắn hạn) để sử dụng cho các bước tiếp theo (đăng ký, hoàn tất reset mật khẩu).
- **Public**: Có (`@IsPublic()`)
- **Request Headers**:
  - `User-Agent`
- **Request Body**: `VerifyCodeBodyDTO`
  ```json
  {
    "email": "user@example.com",
    "code": "123456",
    "type": "REGISTER" // hoặc "RESET_PASSWORD", "LOGIN_UNTRUSTED_DEVICE_OTP"
  }
  ```
- **Authorization**: Không cần.
- **Luồng xử lý**:
  1.  `AuthController.verifyCode` nhận request.
  2.  Gọi `AuthService.verifyCode` (thực chất là `OtpAuthService.verifyCode`).
  3.  `OtpService.verifyOTPAndCreateToken` được gọi:
      - `OtpService.validateVerificationCode`: Kiểm tra code, email, type trong DB, kiểm tra hết hạn.
      - Nếu mã hợp lệ, tạo một `otpToken` (JWT) chứa (email, type, userId (nếu có), deviceId (nếu có), metadata) và có thời gian sống ngắn (ví dụ 5-10 phút). Token này được lưu vào bảng `VerificationToken`.
      - Xóa `VerificationCode` đã sử dụng.
  4.  Ghi Audit Log.
- **Response Body (Success - 201 Created)**: `VerifyCodeResDTO`
  ```json
  {
    "otpToken": "jwt_string_representing_verified_otp_state"
  }
  ```
- **Response Body (Error)**:
  - `422 Unprocessable Entity`: Nếu mã OTP không hợp lệ, hết hạn, hoặc không khớp với email/type.
- **Rủi ro/Cải tiến**:
  - `otpToken` nên chỉ được sử dụng một lần. Logic xóa `VerificationToken` sau khi sử dụng cần được đảm bảo.

---

### Đăng nhập

- **Endpoint**: `POST /auth/login`
- **Mục đích**: Đăng nhập người dùng bằng email và mật khẩu.
- **Public**: Có (`@IsPublic()`)
- **Request Headers**:
  - `User-Agent`
- **Request Body**: `LoginBodyDTO`
  ```json
  {
    "email": "user@example.com",
    "password": "password123",
    "rememberMe": false // optional, default false
  }
  ```
- **Authorization**: Không cần.
- **Luồng xử lý (thành công, không 2FA, không thiết bị lạ)**:
  1.  `AuthController.login` nhận request.
  2.  Gọi `AuthService.login` (thực chất là `AuthenticationService.login`).
  3.  Tìm user bằng email (`SharedUserRepository.findUniqueWithRole`).
  4.  So sánh mật khẩu (`HashingService.compare`).
  5.  `DeviceService.findOrCreateDevice`: Tìm hoặc tạo bản ghi thiết bị dựa trên `userId`, `userAgent`, `ip`. Lấy `deviceId` và `isTrusted`.
  6.  Nếu user bị `BLOCKED` hoặc `INACTIVE`, trả lỗi.
  7.  **Nếu 2FA được bật**:
      - Tạo `loginSessionToken` (JWT ngắn hạn, lưu `userId`, `deviceId`, `isTrusted`, `twoFactorMethod`, `rememberMe`).
      - Lưu `loginSessionToken` vào Redis với key `TOKEN_LOGIN_SESSION`.
      - Trả về response yêu cầu 2FA (xem schema `LoginSessionResSchema`). Client sẽ gọi `/auth/login/verify`.
  8.  **Nếu thiết bị không được tin cậy (`isTrusted` == false) VÀ không có 2FA**:
      - Gửi OTP loại `LOGIN_UNTRUSTED_DEVICE_OTP` (`OtpService.sendOTP`).
      - Tạo `loginSessionToken` (tương tự như trên, nhưng có thể thêm cờ `deviceOtpRequired`).
      - Trả về response yêu cầu OTP thiết bị (schema `LoginSessionResSchema` với message khác). Client sẽ gọi `/auth/login/verify` (dùng chung endpoint, nhưng `type` của code sẽ khác).
  9.  **Nếu đăng nhập thành công (không 2FA, thiết bị tin cậy hoặc đã qua bước OTP thiết bị/2FA)**:
      - `TokenService.generateTokens`: Tạo `accessToken` (JWT) và `refreshTokenJti`.
      - Lưu thông tin session vào Redis (`session:details:<sessionId>`), bao gồm `userId`, `deviceId`, `currentRefreshTokenJti`, `currentAccessTokenJti`, `createdAt`, `lastActiveAt`, `ipAddress`, `userAgent`, `isDeviceTrusted`.
      - Thêm `sessionId` vào set `user:sessions:<userId>`.
      - `TokenService.setTokenCookies`: Gửi `accessToken` trong body (theo `UserProfileResSchema`), `refreshToken` (chứa JTI) trong HTTPOnly cookie.
      - `SessionManagementService.enforceSessionAndDeviceLimits`: Kiểm tra và thu hồi bớt session/thiết bị nếu vượt giới hạn.
      - Ghi Audit Log.
      - Trả về `UserProfileResSchema` chứa thông tin user và `currentDeviceId`.
- **Response Body (Success - 200 OK, trực tiếp)**: `UserProfileResSchema`
  ```json
  {
    "userId": 1,
    "email": "user@example.com",
    "name": "User Name",
    "role": "Client", // Tên vai trò
    "isDeviceTrustedInSession": true, // Dựa trên device.isTrusted khi bắt đầu session
    "currentDeviceId": 123
  }
  ```
- **Response Body (Success - 200 OK, yêu cầu 2FA/OTP thiết bị)**: `LoginSessionResSchema`
  ```json
  // Ví dụ yêu cầu 2FA
  {
    "message": "Two-factor authentication is required. Please verify.", // (Key i18n: error.Auth.Login.2FARequired)
    "loginSessionToken": "jwt_string_for_2fa_step",
    "twoFactorMethod": "TOTP" // hoặc "OTP"
  }
  // Ví dụ yêu cầu OTP thiết bị
  {
    "message": "Untrusted device. OTP has been sent to your email for verification.", // (Key i18n: error.Auth.Login.DeviceVerificationOtpRequired)
    "loginSessionToken": "jwt_string_for_device_otp_step",
    "twoFactorMethod": null // Hoặc một giá trị đặc biệt
  }
  ```
- **Response Body (Error)**:
  - `401 Unauthorized`: Sai email/mật khẩu, user bị khóa/chưa active.
  - `429 Too Many Requests`: Nếu `MaxSessionsReachedException` hoặc `MaxDevicesReachedException` được throw bởi `enforceSessionAndDeviceLimits` (tuy nhiên, hiện tại nó chỉ log và tự động thu hồi, không throw ra client ở bước login).
- **Rủi ro/Cải tiến**:
  - Logic `enforceSessionAndDeviceLimits` hiện không throw lỗi ra client ở bước login mà tự động thu hồi. Điều này có thể gây bất ngờ cho user. Cân nhắc throw `MaxSessionsReachedException` để client có thể hiển thị thông báo phù hợp.
  - Đảm bảo `findOrCreateDevice` ghi nhận đúng `isTrusted` ban đầu.

---

### Làm mới Token

- **Endpoint**: `POST /auth/refresh-token`
- **Mục đích**: Lấy access token mới bằng refresh token.
- **Public**: Có (`@IsPublic()`)
- **Request Headers**:
  - `User-Agent`
  - Cookie chứa refresh token (ví dụ: `shopsifu_rt`).
- **Request Body**: `RefreshTokenBodyDTO` (rỗng)
  ```json
  {}
  ```
- **Authorization**: Không cần (vì dùng refresh token từ cookie).
- **Luồng xử lý**:
  1.  `AuthController.refreshToken` nhận request.
  2.  Gọi `AuthService.refreshToken` (thực chất là `TokenService.refreshTokenSilently`).
  3.  `TokenService.extractRefreshTokenFromRequest`: Lấy JTI của refresh token từ cookie.
  4.  Kiểm tra JTI có bị blacklist không (`USED_REFRESH_TOKEN_JTI`).
  5.  Lấy `sessionId` từ `rt:jti_to_session:<refreshTokenJti>`.
  6.  Lấy chi tiết session từ `session:details:<sessionId>`.
  7.  Xác thực session: `userId`, `deviceId`, `currentRefreshTokenJti` phải khớp. Kiểm tra session có hợp lệ không (ví dụ, không quá tuổi thọ tuyệt đối).
  8.  Nếu tất cả hợp lệ:
      - Đánh dấu `refreshTokenJti` cũ là đã sử dụng (`USED_REFRESH_TOKEN_JTI`).
      - `TokenService.generateTokens`: Tạo `accessToken` mới và `refreshTokenJti` mới.
      - Cập nhật `session:details:<sessionId>` với `currentRefreshTokenJti` mới, `currentAccessTokenJti` mới, `lastActiveAt`.
      - `TokenService.setTokenCookies`: Gửi `accessToken` mới trong body (theo `RefreshTokenSuccessResDTO`), `refreshToken` mới (chứa JTI mới) trong HTTPOnly cookie. Max age của cookie RT có thể được duy trì nếu "rememberMe" được bật.
  9.  Ghi Audit Log.
- **Response Body (Success - 200 OK)**: `RefreshTokenSuccessResDTO`
  ```json
  {
    "message": "Token refreshed successfully." // (Key i18n: error.Auth.Token.Refreshed)
    // Access token mới được gửi trong body (nếu interceptor không sửa đổi) hoặc chỉ có message và token được set trong cookie.
    // Hiện tại schema là RefreshTokenSuccessResDTO chỉ có message, accessToken được set trong cookie bởi setTokenCookies.
    // Tuy nhiên, setTokenCookies chỉ set RT vào cookie, AT thì không.
    // CẦN REVIEW: AuthService.refreshToken trả về { accessToken }, nhưng DTO là RefreshTokenSuccessResDTO.
    // Có thể RefreshTokenSuccessResDTO nên bao gồm accessToken, hoặc client chỉ dựa vào cookie mới.
    // Theo logic hiện tại của setTokenCookies, accessToken KHÔNG được đặt vào cookie. Nó được trả về trong body của refreshTokenSilently.
    // Vậy AuthController.refreshToken cần trả về một DTO chứa accessToken.
    // Đề xuất: Đổi RefreshTokenSuccessResDTO thành AccessTokenResSchema
  }
  ```
  **Sau khi review:** `TokenService.refreshTokenSilently` trả về `{ accessToken, refreshToken (JTI mới), maxAgeForRefreshTokenCookie }`. `AuthController.refreshToken` sau đó gọi `this.tokenService.setTokenCookies(res, newTokens.accessToken, newTokens.refreshToken, newTokens.maxAgeForRefreshTokenCookie)`.
  Hàm `setTokenCookies` hiện tại:
  ```typescript
  setTokenCookies(res: Response, accessToken: string, refreshTokenJti: string, maxAgeForRefreshTokenCookie?: number, isRefreshTokenOnly?: boolean) {
      if (!isRefreshTokenOnly && accessToken) {
          // res.cookie(this.accessTokenCookieConfig.name, accessToken, {...}); // Hiện tại AT không được set vào cookie
      }
      if (refreshTokenJti) {
          res.cookie(this.refreshTokenCookieConfig.name, refreshTokenJti, {...});
      }
  }
  ```
  Và `AuthController.refreshToken` dùng `ZodSerializerDto(RefreshTokenSuccessResDTO)` chỉ có `message`.
  Điều này có nghĩa là **access token mới KHÔNG được gửi về client qua body cũng như cookie.** Đây là một **LỖI NGHIÊM TRỌNG.**
  **Giải pháp:**
  1.  `AuthController.refreshToken` nên sử dụng `@ZodSerializerDto(AccessTokenResSchema)`.
  2.  `AuthService.refreshToken` (hoặc `TokenService.refreshTokenSilently` mà nó gọi) phải trả về một object có trường `accessToken`. Hiện tại `TokenService.refreshTokenSilently` đã làm vậy. `AuthService.refreshToken` cũng trả về đúng. Chỉ có DTO ở controller là sai.
- **Response Body (Error)**:
  - `401 Unauthorized`: Refresh token không hợp lệ, hết hạn, đã sử dụng, session không tìm thấy, session không hợp lệ.
- **Rủi ro/Cải tiến**:
  - **LỖI:** Như đã phân tích, Access Token mới không được gửi về Client. Cần sửa DTO của `POST /auth/refresh-token`.
  - Phát hiện sử dụng lại refresh token (RT reuse detection): Nếu một JTI đã được đánh dấu là "used" nhưng lại được dùng để refresh, đây là dấu hiệu chiếm đoạt session. Tất cả các session của user đó nên bị thu hồi. Logic này cần được thêm vào.

---

### Đăng xuất

- **Endpoint**: `POST /auth/logout`
- **Mục đích**: Đăng xuất người dùng khỏi session hiện tại.
- **Public**: Không (cần Access Token hợp lệ).
- **Request Headers**:
  - `Authorization: Bearer <accessToken>`
  - Cookie chứa refresh token.
- **Request Body**: `LogoutBodyDTO` (rỗng)
  ```json
  {}
  ```
- **Authorization**: Bearer Token.
- **Luồng xử lý**:
  1.  `AuthController.logout` nhận request.
  2.  Gọi `AuthService.logout` (thực chất là `AuthenticationService.logout`).
  3.  `AuthenticationService.logout` gọi `TokenService.logoutSilently(req, res)`.
  4.  `TokenService.logoutSilently`:
      - Lấy `refreshTokenJti` từ cookie.
      - Nếu có `refreshTokenJti`, tìm `sessionId` tương ứng và gọi `TokenService.invalidateSession(sessionId, 'USER_LOGOUT')`.
      - `TokenService.invalidateSession` sẽ:
        - Xóa `session:details:<sessionId>`.
        - Xóa `rt:jti_to_session:<refreshTokenJti>` (nếu có trong session details).
        - Xóa `sessionId` khỏi `user:sessions:<userId>`.
        - Blacklist `accessTokenJti` (nếu có trong session details).
      - `TokenService.clearTokenCookies(res)`: Xóa cookie access token và refresh token.
  5.  Ghi Audit Log.
- **Response Body (Success - 200 OK)**: `MessageResDTO`
  ```json
  {
    "message": "Logout processed. Cookies cleared." // (Key i18n: error.Auth.Logout.Processed)
  }
  ```
- **Response Body (Error)**:
  - `401 Unauthorized`: Nếu access token không hợp lệ.
- **Rủi ro/Cải tiến**:
  - Nếu `accessToken` được gửi nhưng không hợp lệ (ví dụ, hết hạn nhưng chưa bị blacklist), guard sẽ chặn trước. Nếu hợp lệ, `activeUser` sẽ có `sessionId`.
  - Logic hiện tại dường như dựa vào RT JTI từ cookie để tìm session cần invalidate. Nếu RT cookie không có, nó chỉ xóa cookie. Điều này ổn.

---

### Đăng xuất Khỏi Tất Cả Thiết Bị

- **Endpoint**: `POST /auth/logout-all`
- **Mục đích**: Đăng xuất người dùng khỏi tất cả các phiên hoạt động, trừ phiên hiện tại.
- **Public**: Không.
- **Request Headers**:
  - `Authorization: Bearer <accessToken>`
  - `User-Agent`
  - Cookie chứa refresh token (để xác định session hiện tại cần loại trừ).
- **Request Body**: `LogoutBodyDTO` (rỗng)
- **Authorization**: Bearer Token.
- **Luồng xử lý**:
  1.  `AuthController.logoutFromAllDevices` nhận request.
  2.  Lấy `activeUser` (từ `AccessTokenGuard`).
  3.  Gọi `AuthService.logoutFromAllDevices` (thực chất `AuthenticationService.logoutFromAllDevices`).
  4.  `AuthenticationService.logoutFromAllDevices` gọi `TokenService.invalidateAllUserSessions(userId, reason, currentSessionIdToExclude)`.
  5.  `TokenService.invalidateAllUserSessions`:
      - Lấy tất cả `sessionId` từ `user:sessions:<userId>`.
      - Lặp qua từng `sessionId` (trừ `currentSessionIdToExclude`):
        - Gọi `_addSessionInvalidationToPipeline` để thêm các lệnh xóa session, JTI vào pipeline.
      - Thực thi pipeline.
  6.  `TokenService.clearTokenCookies(res)`: Xóa cookie của session hiện tại (vì user muốn "logout all" thì session hiện tại cũng nên kết thúc sau khi các session khác bị xóa). **Cần xem xét lại!** Nếu mục đích là "đăng xuất tất cả các session _khác_", thì không nên clear cookie của session hiện tại.
      - **Review:** Logic của `AuthenticationService.logoutFromAllDevices` KHÔNG clear cookie của session hiện tại. Nó chỉ gọi `invalidateAllUserSessions` với `currentSessionId` để loại trừ. Điều này đúng.
  7.  Ghi Audit Log.
- **Response Body (Success - 200 OK)**: `MessageResDTO`
  ```json
  {
    "message": "Successfully logged out from all other devices." // (Cần key i18n mới)
  }
  ```
- **Rủi ro/Cải tiến**:
  - Cần một key i18n mới cho thông báo thành công, ví dụ `Auth.Logout.AllExceptCurrentSuccess`.

---

### Đăng nhập bằng Google

- **Endpoint 1**: `GET /auth/google-link`

  - **Mục đích**: Lấy URL ủy quyền của Google để redirect người dùng.
  - **Public**: Có.
  - **Request Params**: `userAgent`, `ip` (lấy tự động).
  - **Response**: `GetAuthorizationUrlResDTO` (`{ "url": "https://google.com/auth/url..." }`)
  - **Luồng**: `GoogleService.getAuthorizationUrl` tạo state (chứa `userAgent`, `ip`, `rememberMe`), mã hóa và trả về URL của Google với state đó. State được lưu vào Redis (`google_auth_state:<hashed_state>`).

- **Endpoint 2**: `GET /auth/google/callback`
  - **Mục đích**: Xử lý callback từ Google sau khi người dùng ủy quyền.
  - **Public**: Có.
  - **Query Params**: `code`, `state`.
  - **Luồng**:
    1.  `GoogleService.googleCallback` xử lý.
    2.  Xác thực `state` (lấy từ Redis, so sánh). Lấy lại `userAgent`, `ip` từ state đã lưu.
    3.  Dùng `code` để lấy token từ Google.
    4.  Dùng token của Google để lấy thông tin user (email, name, avatar).
    5.  Tìm user trong DB bằng email:
        - **Nếu user tồn tại**:
          - `DeviceService.findOrCreateDevice`.
          - Kiểm tra 2FA, thiết bị lạ (tương tự luồng login thường).
          - Nếu cần 2FA/OTP thiết bị, redirect về frontend với `loginSessionToken`.
          - Nếu không, tạo session, token và redirect về frontend với token đã set trong cookie hoặc trả JSON (hiện tại trả JSON).
        - **Nếu user không tồn tại**:
          - Tạo user mới (mật khẩu ngẫu nhiên hoặc không có, `status: ACTIVE`).
          - `DeviceService.findOrCreateDevice`.
          - Tạo session, token và redirect/trả JSON.
    6.  Ghi Audit Log.
  - **Response**: Redirect về `envConfig.GOOGLE_CLIENT_REDIRECT_URI` với các query param (thành công hoặc lỗi). Nếu thành công và không cần bước trung gian, có thể trả JSON chứa token (nhưng hiện tại là redirect và client tự xử lý).
    - **Cần review:** Cách trả response của `/google/callback` khá phức tạp, có cả redirect và trả JSON. Nên thống nhất một kiểu. Redirect thường phổ biến hơn cho OAuth2 callback. Nếu redirect, token cần được truyền an toàn (ví dụ, server-side session hoặc một mã dùng một lần để client đổi lấy token). Hiện tại đang set cookie server-side rồi redirect, hoặc redirect với `loginSessionToken` cho 2FA.
- **Rủi ro/Cải tiến**:
  - Bảo mật `state` trong OAuth2.
  - Xử lý trường hợp email từ Google đã được dùng cho tài khoản thường (có mật khẩu). Có thể cần liên kết tài khoản.
  - Thống nhất cách trả response cho `/google/callback`.

---

### Đặt lại Mật khẩu

- **Giai đoạn 1: Gửi OTP (Xem `POST /auth/send-otp` với `type: "RESET_PASSWORD"`)**
- **Giai đoạn 2: Xác minh OTP và Tạo `otpToken` (Xem `POST /auth/verify-code` với `type: "RESET_PASSWORD"`)**
- **Giai đoạn 3: Thực hiện Đặt lại Mật khẩu**
  - **Endpoint**: `POST /auth/reset-password`
  - **Mục đích**: Đặt mật khẩu mới cho người dùng sau khi đã xác minh OTP.
  - **Public**: Có.
  - **Request Headers**: `User-Agent`.
  - **Request Body**: `ResetPasswordBodyDTO`
    ```json
    {
      "email": "user@example.com",
      "otpToken": "jwt_otp_token_from_verify_code_step_for_reset_password",
      "newPassword": "newPassword123",
      "confirmNewPassword": "newPassword123"
    }
    ```
  - **Luồng xử lý**:
    1.  `AuthController.resetPassword`.
    2.  Gọi `AuthService.resetPassword` (thực chất là `PasswordAuthService.resetPassword`).
    3.  `OtpService.validateVerificationToken`: Xác thực `otpToken` (loại `RESET_PASSWORD`, email phải khớp).
    4.  Tìm user bằng email.
    5.  Hash mật khẩu mới.
    6.  Cập nhật mật khẩu user trong DB.
    7.  `TokenService.invalidateAllUserSessions`: Thu hồi tất cả các session của user đó (quan trọng để bảo mật).
    8.  Xóa `otpToken` đã sử dụng.
    9.  Ghi Audit Log.
    10. Gửi email thông báo mật khẩu đã được đặt lại (`EmailService.sendSecurityAlertEmail`).
  - **Response Body (Success - 200 OK)**: `MessageResDTO`
    ```json
    {
      "message": "Password has been reset successfully." // (Key i18n: error.Auth.Password.ResetSuccess)
    }
    ```
  - **Response Body (Error)**:
    - `422 Unprocessable Entity`: `otpToken` không hợp lệ/hết hạn, mật khẩu mới không hợp lệ/không khớp.
    - `404 Not Found`: Email không tồn tại.
- **Rủi ro/Cải tiến**:
  - Đảm bảo `invalidateAllUserSessions` được gọi để tăng cường bảo mật.

---

### Quản lý Xác thực Hai Yếu tố (2FA)

#### Thiết lập 2FA (TOTP)

- **Endpoint**: `POST /auth/2fa/setup`
- **Mục đích**: Bắt đầu quá trình thiết lập 2FA bằng TOTP. Trả về secret và URI cho mã QR.
- **Authorization**: Bearer Token.
- **Request Body**: `EmptyBodyDTO`.
- **Luồng**:
  1.  `AuthController.setupTwoFactorAuth`.
  2.  Gọi `AuthService.setupTwoFactorAuth` (thực chất `TwoFactorAuthService.setupTwoFactorAuth`).
  3.  Kiểm tra user đã bật 2FA chưa.
  4.  `TwoFactorService.generateTOTPSecret`: Tạo secret mới.
  5.  Tạo `setupToken` (JWT ngắn hạn, chứa `userId` và `totpSecret`). Lưu vào Redis với key `TOKEN_2FA_SETUP`.
  6.  Tạo OTPAuth URI từ secret.
- **Response Body (Success - 201 Created)**: `TwoFactorSetupResDTO`
  ```json
  {
    "secret": "BASE32_ENCODED_SECRET",
    "uri": "otpauth://totp/Shopsifu:user@example.com?secret=BASE32_ENCODED_SECRET&issuer=Shopsifu",
    "setupToken": "jwt_setup_token"
  }
  ```

#### Xác nhận Thiết lập 2FA (TOTP)

- **Endpoint**: `POST /auth/2fa/confirm-setup`
- **Mục đích**: Xác nhận thiết lập 2FA bằng cách cung cấp mã TOTP từ authenticator app.
- **Authorization**: Bearer Token.
- **Request Body**: `TwoFactorConfirmSetupBodyDTO`
  ```json
  {
    "setupToken": "jwt_setup_token_from_setup_step",
    "totpCode": "123456" // Mã từ app
  }
  ```
- **Luồng**:
  1.  `AuthController.confirmTwoFactorSetup`.
  2.  Gọi `AuthService.confirmTwoFactorSetup` (thực chất `TwoFactorAuthService.confirmTwoFactorSetup`).
  3.  Xác thực `setupToken` (lấy `userId`, `totpSecret` từ token và Redis).
  4.  `TwoFactorService.verifyTOTP`: Xác minh `totpCode` với `totpSecret`.
  5.  Nếu hợp lệ:
      - `TwoFactorService.updateUserTwoFactorStatus`: Cập nhật DB (user: `twoFactorEnabled=true`, `twoFactorSecret`, `twoFactorMethod='TOTP'`, `twoFactorVerifiedAt`).
      - `TwoFactorService.generateRecoveryCodes`: Tạo mã khôi phục.
      - `TwoFactorService.saveRecoveryCodes`: Lưu mã khôi phục (hashed) vào DB.
      - Xóa `setupToken` khỏi Redis.
      - Gửi email thông báo 2FA đã bật.
      - Ghi Audit Log.
- **Response Body (Success - 201 Created)**: `TwoFactorConfirmSetupResDTO`
  ```json
  {
    "message": "2FA has been confirmed and enabled. Please save your recovery codes.", // (Key i18n: error.Auth.2FA.Confirm.Success)
    "recoveryCodes": ["code1", "code2", ...] // Mã khôi phục dạng plain text
  }
  ```

#### Vô hiệu hóa 2FA

- **Endpoint**: `POST /auth/2fa/disable`
- **Mục đích**: Vô hiệu hóa 2FA cho tài khoản.
- **Authorization**: Bearer Token.
- **Request Body**: `DisableTwoFactorBodyDTO`
  ```json
  {
    "type": "TOTP", // "TOTP" hoặc "RECOVERY" (nếu dùng mã khôi phục để tắt)
    "code": "123456" // Mã TOTP hoặc mã khôi phục
  }
  ```
- **Luồng**:
  1.  `AuthController.disableTwoFactorAuth`.
  2.  Gọi `AuthService.disableTwoFactorAuth` (thực chất `TwoFactorAuthService.disableTwoFactorAuth`).
  3.  Kiểm tra user có bật 2FA không.
  4.  Xác thực `code` (TOTP hoặc recovery code) dựa trên `type`.
  5.  Nếu hợp lệ:
      - `TwoFactorService.updateUserTwoFactorStatus`: Cập nhật DB (user: `twoFactorEnabled=false`, xóa secret, method).
      - `TwoFactorService.deleteAllRecoveryCodes`.
      - Gửi email thông báo 2FA đã tắt.
      - Ghi Audit Log.
- **Response Body (Success - 200 OK)**: `MessageResDTO`
  ```json
  {
    "message": "Two-factor authentication has been disabled successfully." // (Key i18n: error.Auth.2FA.Disabled)
  }
  ```

#### Xác minh Đăng nhập bằng 2FA (sau bước username/password)

- **Endpoint**: `POST /auth/login/verify`
- **Mục đích**: Hoàn tất quá trình đăng nhập khi 2FA được yêu cầu hoặc OTP cho thiết bị lạ được yêu cầu.
- **Public**: Có.
- **Request Headers**: `User-Agent`.
- **Request Body**: `TwoFactorVerifyBodyDTO`
  ```json
  {
    "loginSessionToken": "jwt_from_login_step_requiring_2fa_or_device_otp",
    "type": "TOTP", // hoặc "OTP" (cho OTP thiết bị/email), "RECOVERY"
    "code": "123456"
  }
  ```
- **Luồng**:
  1.  `AuthController.verifyTwoFactor`.
  2.  Gọi `AuthService.verifyTwoFactor` (thực chất `TwoFactorAuthService.verifyTwoFactor`).
  3.  Xác thực `loginSessionToken` (lấy `userId`, `deviceId`, `isTrusted` ban đầu, `rememberMe`, `twoFactorMethod` từ token và Redis).
  4.  Dựa vào `type` và `twoFactorMethod` (từ user hoặc từ `loginSessionToken`):
      - Nếu `type` là `TOTP`: Xác minh `code` với `user.twoFactorSecret`.
      - Nếu `type` là `OTP` (dùng cho `LOGIN_UNTRUSTED_DEVICE_OTP` hoặc nếu user chọn OTP qua email cho 2FA): Gọi `OtpService.validateVerificationCode` với `type = LOGIN_UNTRUSTED_DEVICE_OTP` hoặc `LOGIN_2FA`.
      - Nếu `type` là `RECOVERY`: Xác minh mã khôi phục.
  5.  Nếu xác minh thành công:
      - `DeviceService.trustDevice(deviceId, userId)`: Nếu đây là bước OTP cho thiết bị lạ và thành công, thiết bị sẽ được trust.
      - Cập nhật `user.twoFactorVerifiedAt` (nếu là lần đầu xác minh 2FA sau khi bật).
      - Xóa `loginSessionToken` khỏi Redis.
      - Tạo session, access/refresh token (tương tự luồng login thành công).
      - `SessionManagementService.enforceSessionAndDeviceLimits`.
      - Set cookie.
      - Ghi Audit Log.
- **Response Body (Success - 200 OK)**: `UserProfileResSchema` (tương tự login thành công).
- **Rủi ro/Cải tiến**:
  - Phân biệt rõ ràng `type` trong `TwoFactorVerifyBodyDTO` và mục đích của `loginSessionToken`. Nếu `loginSessionToken` chứa thông tin là cần OTP thiết bị, thì `type` phải là `OTP`. Nếu là 2FA, thì `type` có thể là `TOTP` hoặc `RECOVERY`.

---

### Quản lý Phiên & Thiết bị

#### Lấy Danh sách Phiên Hoạt Động

- **Endpoint**: `GET /auth/sessions`
- **Mục đích**: Lấy danh sách các phiên đang hoạt động của người dùng.
- **Authorization**: Bearer Token.
- **Query Params**: `GetActiveSessionsQueryDTO`
  - `deviceId?: number`: Lọc session theo một thiết bị cụ thể.
- **Luồng**:
  1.  `AuthController.getActiveSessions`.
  2.  Gọi `SessionManagementService.getActiveSessions`.
  3.  Lấy tất cả `sessionId` từ `user:sessions:<userId>` (Redis).
  4.  Dùng pipeline lấy chi tiết tất cả các session từ `session:details:<sessionId>`.
  5.  Lọc theo `deviceId` (nếu có).
  6.  Lấy thông tin thiết bị (`name`, `isTrusted`) từ DB cho các `deviceId` liên quan.
  7.  Parse User-Agent, lấy thông tin vị trí từ IP.
  8.  Định dạng dữ liệu trả về.
- **Response Body (Success - 200 OK)**: `GetActiveSessionsResDTO` (PaginatedResponseType của `ActiveSessionSchema`)
  ```json
  {
    "data": [
      {
        "sessionId": "unique_session_id_1",
        "device": {
          "id": 123,
          "name": "My Chrome Browser",
          "type": "desktop", // 'mobile', 'tablet', 'desktop', 'tv', 'unknown'
          "os": "Windows 10",
          "browser": "Chrome 100",
          "isCurrentDevice": true
        },
        "ipAddress": "123.45.67.89",
        "location": "Hanoi, Vietnam",
        "loggedInAt": "2023-10-27T10:00:00.000Z",
        "lastActiveAt": "2023-10-27T12:00:00.000Z",
        "isCurrentSession": true
      }
      // ... other sessions
    ],
    "totalItems": 1,
    "page": 1,
    "limit": 1,
    "totalPages": 1
  }
  ```

#### Thu hồi Phiên Đơn lẻ

- **Endpoint**: `DELETE /auth/sessions/:sessionId`
- **Mục đích**: Thu hồi một phiên hoạt động cụ thể (không phải phiên hiện tại).
- **Authorization**: Bearer Token.
- **URL Params**: `sessionId`
- **Luồng**:
  1.  `AuthController.revokeSession`.
  2.  Gọi `SessionManagementService.revokeSession`.
  3.  Kiểm tra `sessionIdToRevoke` không phải là `currentSessionId`.
  4.  Kiểm tra session tồn tại và thuộc về user.
  5.  `TokenService.invalidateSession(sessionIdToRevoke)`.
- **Response Body (Success - 200 OK)**: `MessageResDTO` (`{ "message": "Session has been revoked successfully." }`)

#### Thu hồi Nhiều Phiên / Phiên của Thiết bị / Tất cả Phiên Khác

- **Endpoint**: `DELETE /auth/sessions`
- **Mục đích**: Thu hồi phiên linh hoạt dựa trên body request.
- **Authorization**: Bearer Token.
- **Request Body**: `RevokeSessionsBodyDTO`

  ```json
  // Thu hồi các session cụ thể (trừ session hiện tại nếu có trong list)
  { "sessionIds": ["session_id_2", "session_id_3"] }

  // Thu hồi tất cả session của một thiết bị và untrust thiết bị đó
  { "deviceId": 456 }

  // Thu hồi tất cả session của user trừ session hiện tại
  { "revokeAll": true }
  ```

- **Luồng**:
  1.  `AuthController.revokeMultipleSessions`.
  2.  Gọi `SessionManagementService.revokeMultipleSessions`.
  3.  Xử lý logic dựa trên `revokeAll`, `deviceId`, hoặc `sessionIds`.
      - Nếu `revokeAll`: Lấy tất cả session của user, loại trừ session hiện tại, rồi thu hồi.
      - Nếu `deviceId`: Lấy tất cả session của device, thu hồi, sau đó gọi `untrustManagedDevice`.
      - Nếu `sessionIds`: Thu hồi các session được chỉ định (loại trừ session hiện tại).
  4.  Sử dụng `TokenService.invalidateSession` cho từng session.
  5.  Ghi Audit Log.
- **Response Body (Success - 200 OK)**: `MessageResDTO` (ví dụ: `{ "message": "Successfully revoked 2 session(s)." }`)

#### Lấy Danh sách Thiết bị Được Quản lý

- **Endpoint**: `GET /auth/devices`
- **Mục đích**: Lấy danh sách các thiết bị đã được ghi nhận cho người dùng.
- **Authorization**: Bearer Token.
- **Luồng**:
  1.  `AuthController.getManagedDevices`.
  2.  Gọi `SessionManagementService.getManagedDevices`.
  3.  Lấy tất cả thiết bị từ DB cho `userId`.
  4.  Parse User-Agent, lấy thông tin vị trí.
- **Response Body (Success - 200 OK)**: `GetDevicesResDTO` (PaginatedResponseType của `DeviceInfoSchema`)
  ```json
  {
    "data": [
      {
        "id": 123,
        "name": "My Chrome Browser",
        "type": "desktop",
        "os": "Windows 10",
        "browser": "Chrome 100",
        "ip": "123.45.67.89",
        "location": "Hanoi, Vietnam",
        "createdAt": "2023-10-26T10:00:00.000Z",
        "lastActive": "2023-10-27T12:00:00.000Z",
        "isTrusted": true
      }
    ]
    // ... pagination info
  }
  ```

#### Cập nhật Tên Thiết bị

- **Endpoint**: `PATCH /auth/devices/:deviceId/name`
- **Authorization**: Bearer Token.
- **URL Params**: `deviceId`.
- **Request Body**: `UpdateDeviceNameBodyDTO` (`{ "name": "New Device Name" }`)
- **Luồng**: `SessionManagementService.updateDeviceName` cập nhật tên device trong DB.
- **Response**: `MessageResDTO`.

#### Tin cậy Thiết bị Được Quản lý

- **Endpoint**: `POST /auth/devices/:deviceId/trust`
- **Authorization**: Bearer Token.
- **URL Params**: `deviceId`.
- **Request Body**: `EmptyBodyDTO`.
- **Luồng**:
  1.  `SessionManagementService.trustManagedDevice`.
  2.  `DeviceService.trustDevice`: Cập nhật `isTrusted = true` cho device trong DB.
  3.  Cập nhật tất cả session Redis của device đó: `hset(sessionDetailsKey, 'isTrusted', 'true')`.
- **Response**: `MessageResDTO`.

#### Bỏ tin cậy Thiết bị Được Quản lý

- **Endpoint**: `POST /auth/devices/:deviceId/untrust`
- **Authorization**: Bearer Token.
- **URL Params**: `deviceId`.
- **Request Body**: `EmptyBodyDTO`.
- **Luồng**:
  1.  `SessionManagementService.untrustManagedDevice`.
  2.  Cập nhật `isTrusted = false` cho device trong DB.
  3.  Cập nhật tất cả session Redis của device đó: `hset(sessionDetailsKey, 'isTrusted', 'false')`.
- **Response**: `MessageResDTO`.

#### Đăng xuất Khỏi Thiết bị Được Quản lý (Deprecated)

- **Endpoint**: `POST /auth/devices/:deviceId/logout`
  - **Đã deprecated, sử dụng `DELETE /auth/sessions` với body `{ "deviceId": <id> }` thay thế.**
- **Luồng cũ**: `SessionManagementService.logoutFromManagedDevice` thu hồi tất cả session Redis của device đó. _Không_ untrust device.

#### Tin cậy Thiết bị Hiện tại

- **Endpoint**: `POST /auth/sessions/current/trust-device`
- **Mục đích**: Cho phép người dùng tin cậy thiết bị mà họ đang sử dụng để thực hiện request này.
- **Authorization**: Bearer Token.
- **Request Body**: `EmptyBodyDTO`.
- **Luồng**:
  1.  `AuthController.trustCurrentDevice`.
  2.  Lấy `userId` và `deviceId` (của session hiện tại) từ `activeUser` (payload của access token).
  3.  Gọi `SessionManagementService.trustCurrentDevice`.
  4.  Logic tương tự `trustManagedDevice`: `DeviceService.trustDevice` và cập nhật các session Redis.
- **Response**: `MessageResDTO`.

---

## 5. Rủi ro và Cải tiến Tiềm năng

- **Lỗi Refresh Token**: Endpoint `POST /auth/refresh-token` hiện không trả về `accessToken` mới cho client một cách đúng đắn qua body response. Cần sửa DTO thành `AccessTokenResSchema`.
- **Rate Limiting**: Cần rà soát và áp dụng rate limiting một cách nhất quán và chặt chẽ hơn cho các endpoint nhạy cảm (login, send-otp, verify-code, reset-password, 2FA operations). ThrottlerModule đã được setup, cần đảm bảo các decorator `@Throttle` được dùng đúng.
- **RT Reuse Detection**: Triển khai cơ chế phát hiện và xử lý việc sử dụng lại refresh token đã hết hạn hoặc đã được dùng. Khi phát hiện, thu hồi tất cả session của user đó.
- **Thông báo Giới hạn Session/Device**: Khi `enforceSessionAndDeviceLimits` tự động thu hồi session/device, nên cân nhắc việc gửi thông báo (email hoặc trong ứng dụng) cho người dùng, hoặc throw lỗi ở bước login để client xử lý.
- **CSRF Protection**: `CsrfMiddleware` đã được áp dụng. Cần đảm bảo client gửi `X-CSRF-Token` đúng cách cho các request thay đổi trạng thái (POST, PUT, PATCH, DELETE).
- **Audit Logging**: Đảm bảo tất cả các hành động quan trọng, đặc biệt là các thay đổi trạng thái và lỗi bảo mật, đều được ghi log chi tiết. Interceptor `AuditLogInterceptor` và decorator `@AuditLog` đã có, cần kiểm tra độ bao phủ.
- **User-Agent Parsing và Device Fingerprinting**:
  - Logic `_normalizeDeviceType` và `basicDeviceFingerprint` đã được cải thiện. Cần theo dõi hiệu quả và độ chính xác của việc nhận diện thiết bị.
  - Fingerprint hiện tại (`ua-parser-js` output + IP prefix) có thể chưa đủ mạnh mẽ để chống lại các kỹ thuật giả mạo tinh vi. Cân nhắc tích hợp các thư viện fingerprinting phía client nếu cần độ chính xác cao hơn.
- **Google Callback Response**: Thống nhất cách trả response (ưu tiên redirect chuẩn OAuth2 và truyền token/code an toàn).
- **Đồng bộ i18n keys**: Tự động hóa việc tạo `i18n.generated.ts`.
- **Xử lý lỗi chi tiết hơn từ `ua-parser-js`**: Nếu `ua-parser-js` trả về các giá trị không mong muốn cho OS, browser, device type, hệ thống nên có cách xử lý mềm dẻo hơn thay vì chỉ dựa vào enum cứng nhắc (đã cải thiện phần nào với `_normalizeDeviceType`).
- **Test Coverage**: Tăng cường unit test và e2e test cho các luồng xác thực và quản lý session/thiết bị.
- **Vòng đời Session trên Redis**: Đảm bảo `ABSOLUTE_SESSION_LIFETIME_MS` được áp dụng nhất quán. Hiện tại, `AccessTokenGuard` kiểm tra tuổi session. `session:details` trên Redis nên có TTL tương ứng hoặc được dọn dẹp định kỳ.
- **Password Policy**: Xem xét việc áp dụng chính sách mật khẩu mạnh hơn (độ dài, ký tự đặc biệt, không trùng mật khẩu cũ) ở cả frontend và backend.

Đây là một tài liệu khá chi tiết. Hy vọng nó sẽ giúp ích cho việc phát triển tiếp theo!
