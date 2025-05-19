# Endpoint: `POST /auth/register` - Đăng ký tài khoản

## 1. Mô tả

Endpoint này hoàn tất quá trình đăng ký người dùng mới sau khi email của họ đã được xác minh thông qua luồng OTP (`/send-otp` -> `/verify-code`). Người dùng gửi thông tin cá nhân (tên, mật khẩu) cùng với `verificationToken` (UUID) nhận được từ `/verify-code`.

Nếu thành công, một tài khoản người dùng mới sẽ được tạo, `verificationToken` sẽ bị vô hiệu hóa (sử dụng), và người dùng sẽ tự động đăng nhập (nhận `accessToken` và `refreshToken` qua cookies, cùng thông tin profile).

## 2. Decorators

- `@IsPublic()`: Endpoint này công khai.
- `@HttpCode(HttpStatus.CREATED)`: Trả về HTTP status 201 khi đăng ký thành công.
- `@ZodSerializerDto(UserProfileResDTO)`: Response trả về thông tin người dùng (không bao gồm mật khẩu), tương tự như khi đăng nhập thành công.
- `@Throttle({ medium: { limit: 10, ttl: 60000 } })`: Giới hạn tần suất truy cập.

## 3. Request

- **Body:** `RegisterBodyDTO`
  ```json
  {
    "verificationToken": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy", // UUID từ /auth/verify-code
    "name": "John Doe",
    "password": "password123",
    "confirmPassword": "password123"
  }
  ```
  - `verificationToken` (string, required, uuid format): UUID token nhận được từ `/auth/verify-code` sau khi xác thực OTP thành công.
  - `name` (string, required): Tên của người dùng.
  - `password` (string, required, min length 8, phức tạp theo yêu cầu): Mật khẩu người dùng.
  - `confirmPassword` (string, required): Phải trùng khớp với `password`.
- **Headers (Tự động lấy bởi decorators):**
  - `User-Agent`: Lấy bởi `@UserAgent()` decorator.
  - `Client IP`: Lấy bởi `@Ip()` decorator.
- **Cookies (BE sẽ thiết lập khi thành công):**
  - `access_token`
  - `refresh_token`

## 4. Response

**4.1. Thành công (Đăng ký và tự động đăng nhập):**

- **Status Code:** 201 Created
- \*\*Body (Serialized bởi `UserProfileResSchema`):
  ```json
  {
    "statusCode": 201,
    "message": "Auth.Register.Success", // i18n key
    "data": {
      "userId": 123,
      "email": "user@example.com", // Lấy từ verificationToken
      "name": "John Doe",
      "role": "CLIENT" // Vai trò mặc định khi đăng ký
    }
  }
  ```
- **Cookies được thiết lập:**
  - `access_token`: Chứa JWT Access Token.
  - `refresh_token`: Chứa JWT Refresh Token (UUID).

**4.2. Lỗi:**

- **400 Bad Request (`InvalidVerificationTokenException`, `VerificationTokenExpiredException`, `VerificationTokenAlreadyUsedException`, `UserAlreadyExistsException` (hiếm khi xảy ra ở bước này nếu luồng OTP đúng)):**
  - `InvalidVerificationTokenException`: Nếu `verificationToken` (UUID) không hợp lệ, không tìm thấy, hoặc không có `type` là `REGISTER` hoặc `tokenType` là `VERIFICATION`.
  - `VerificationTokenExpiredException`: Nếu `verificationToken` đã hết hạn.
  - `VerificationTokenAlreadyUsedException`: Nếu `verificationToken` đã được sử dụng để đăng ký trước đó (trường `usedAt` đã có giá trị).
  - `UserAlreadyExistsException`: Trường hợp hi hữu nếu email từ `verificationToken` lại bị trùng trong DB (có thể do race condition hoặc lỗi logic trước đó, nhưng `send-otp` đã kiểm tra).
  ```json
  {
    "type": "https://api.shopsifu.live/errors/bad-request", // Hoặc type cụ thể hơn
    "title": "Bad Request",
    "status": 400,
    "description": "Error.Auth.Token.InvalidVerification", // Hoặc Expired, AlreadyUsed
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid"
  }
  ```
- **422 Unprocessable Entity (Validation Error):** Nếu request body không hợp lệ (ví dụ: mật khẩu không khớp, tên quá ngắn, `verificationToken` thiếu).
- **409 Conflict (`DefaultRoleNotFoundException`):** Nếu vai trò mặc định ('CLIENT') không được tìm thấy trong hệ thống khi cố gắng gán cho người dùng mới.
- **500 Internal Server Error (`UserCreationException`, `DeviceSetupFailedException`):**
  - `UserCreationException`: Nếu có lỗi khi tạo bản ghi người dùng mới trong DB.
  - `DeviceSetupFailedException`: Nếu có lỗi khi xử lý thông tin thiết bị cho lần đăng nhập đầu tiên.

## 5. Luồng Hoạt động (Backend - `AuthService.register`)

1.  **Validation:** Dữ liệu request (`verificationToken`, `name`, `password`, `confirmPassword`) được validate bởi `RegisterBodyDTO` (bao gồm cả việc `password` và `confirmPassword` phải khớp).
2.  **Audit Logging:** Bắt đầu ghi log (`action: 'USER_REGISTER_ATTEMPT'`).
3.  **Prisma Transaction:** Các thao tác DB được thực hiện trong một transaction.
4.  **Xác thực `VerificationToken`:**
    - Gọi `AuthRepository.findVerificationToken(body.verificationToken)`.
    - **Nếu không tìm thấy, hoặc `token.type` không phải `REGISTER`, hoặc `token.tokenType` không phải `VERIFICATION`, hoặc `token.verified` không phải `true`:** Ném `InvalidVerificationTokenException`.
    - **Nếu `token.usedAt` đã có giá trị:** Ném `VerificationTokenAlreadyUsedException`.
    - **Nếu `token.expiresAt` < `new Date()`:** Ném `VerificationTokenExpiredException`.
    - Lấy `email` từ `verificationTokenRecord.email` (đây là email đã được xác minh).
    - Ghi lại `email` cho audit log.
5.  **Kiểm tra lại sự tồn tại của User (đề phòng):**
    - Gọi `AuthRepository.findUserByEmail(emailFromToken)`.
    - **Nếu user đã tồn tại:** Ném `UserAlreadyExistsException` (dù đã kiểm tra ở `send-otp`, đây là bước kiểm tra cuối cùng).
6.  **Hash Mật khẩu:** Gọi `HashingService.hash(body.password)` để hash mật khẩu người dùng cung cấp.
7.  **Tìm Vai trò Mặc định:**
    - Gọi `RolesService.findRoleByName(DefaultUserRoles.CLIENT)` để lấy thông tin vai trò 'CLIENT'.
    - **Nếu không tìm thấy vai trò 'CLIENT':** Ném `DefaultRoleNotFoundException`.
8.  **Tạo Người dùng Mới:**
    - Gọi `AuthRepository.createUser` với các thông tin:
      - `email`: `emailFromToken`.
      - `name`: `body.name`.
      - `password`: Mật khẩu đã hash.
      - `roleId`: ID của vai trò 'CLIENT'.
      - `isEmailVerified`: `true` (vì đã qua bước OTP).
    - **Nếu tạo user thất bại:** Ném `UserCreationException`.
    - Lấy `createdUser.id` và `createdUser.role.name`.
9.  **Đánh dấu `VerificationToken` là đã sử dụng:**
    - Cập nhật bản ghi `VerificationToken` (tìm bằng `body.verificationToken`), set `usedAt: new Date()` và `userId: createdUser.id`.
10. **Xử lý Thiết bị và Tạo Tokens (Tự động đăng nhập):**
    - Gọi `AuthRepository.findOrCreateDevice` với `createdUser.id`, `userAgent`, `ip` để lấy hoặc tạo `deviceId`. Nếu lỗi, ném `DeviceSetupFailedException`.
    - Gọi `AuthService.generateTokens` với `createdUser.id`, `deviceId`, `role.id`, `role.name` và `rememberMe: false` (mặc định cho đăng ký).
    - `generateTokens` trả về `accessToken`, `refreshToken` (UUID), và `maxAgeForRefreshTokenCookie`.
11. **Thiết lập Cookies:** Nếu có `res` object, gọi `TokenService.setTokenCookies` để thiết lập `access_token` và `refresh_token` vào HTTP response cookies.
12. **Audit Logging:** Ghi log thành công (`action: 'USER_REGISTER_SUCCESS'`).
13. **Trả về Response:** Trả về thông tin người dùng: `{ userId: createdUser.id, email: createdUser.email, name: createdUser.name, role: createdUser.role.name }`.

## 6. Tương tác FE/BE

1.  **FE:** Sau khi xác minh OTP thành công (`POST /auth/verify-code`) và nhận được `verificationToken` (UUID mới).
    - FE hiển thị form cho người dùng nhập tên, mật khẩu, và xác nhận mật khẩu.
2.  **FE Call API:** Khi người dùng điền đủ thông tin và nhấn "Đăng ký", FE gọi `POST /auth/register` với `verificationToken` (UUID đã lưu), `name`, `password`, `confirmPassword`.
3.  **BE:** Xử lý như mục 5.
    - Xác thực `verificationToken`.
    - Tạo user mới, hash mật khẩu, gán vai trò mặc định.
    - Đánh dấu `verificationToken` là đã sử dụng.
    - Tạo tokens (access & refresh), thiết lập cookies.
    - Trả về thông tin user profile.
4.  **FE:**
    - Nếu BE trả về **201 Created** với thông tin user:
      - Đăng ký thành công. FE lưu thông tin user vào state/context.
      - Xóa `verificationToken` khỏi state.
      - Chuyển hướng người dùng đến trang dashboard hoặc trang chào mừng.
      - Cookies `access_token` và `refresh_token` đã được BE tự động thiết lập.
    - Nếu BE trả về **lỗi** (400 token không hợp lệ/hết hạn/đã dùng, 422 validation, 409, 500...): Hiển thị thông báo lỗi tương ứng. Người dùng có thể cần bắt đầu lại quy trình đăng ký hoặc sửa lỗi nhập liệu.

## 7. Điểm nổi bật & Lưu ý

- **Ủy quyền bằng `verificationToken`:** `verificationToken` đảm bảo rằng chỉ người dùng đã xác minh email mới có thể tiến tới bước tạo tài khoản với email đó.
- **`verificationToken` chỉ dùng một lần:** Ngăn chặn việc sử dụng lại cùng một token để tạo nhiều tài khoản.
- **Tự động Đăng nhập:** Sau khi đăng ký thành công, người dùng được tự động đăng nhập, cải thiện trải nghiệm người dùng.
- **Vai trò Mặc định:** Người dùng mới được gán vai trò 'CLIENT' theo mặc định.
- **Bảo mật Mật khẩu:** Mật khẩu được hash trước khi lưu.
- **Audit Logging:** Ghi lại các nỗ lực và kết quả đăng ký.
