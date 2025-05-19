# Endpoint: `POST /auth/reset-password` - Đặt lại mật khẩu

## 1. Mô tả

Endpoint này cho phép người dùng đặt lại mật khẩu của họ sau khi đã xác minh quyền sở hữu email thông qua luồng OTP (sử dụng `type: "FORGOT_PASSWORD"` trong `/send-otp` và sau đó là `/verify-code`). Người dùng gửi mật khẩu mới cùng với `verificationToken` (UUID) nhận được từ `/verify-code`.

Nếu thành công, mật khẩu của người dùng sẽ được cập nhật, `verificationToken` sẽ bị vô hiệu hóa, và tất cả các `refreshToken` (phiên đăng nhập) hiện có của người dùng đó trên mọi thiết bị sẽ bị xóa để đảm bảo an toàn.

## 2. Decorators

- `@IsPublic()`: Endpoint này công khai.
- `@HttpCode(HttpStatus.OK)`: Trả về HTTP status 200 khi đặt lại mật khẩu thành công.
- `@ZodSerializerDto(BaseResDTO)`: Response trả về chỉ chứa message thành công chung.
- `@Throttle({ medium: { limit: 5, ttl: 60000 } })`: Giới hạn tần suất truy cập.

## 3. Request

- **Body:** `ResetPasswordBodyDTO`
  ```json
  {
    "verificationToken": "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", // UUID từ /auth/verify-code (cho type FORGOT_PASSWORD)
    "password": "newStrongPassword123",
    "confirmPassword": "newStrongPassword123"
  }
  ```
  - `verificationToken` (string, required, uuid format): UUID token nhận được từ `/auth/verify-code` sau khi xác thực OTP cho mục đích quên mật khẩu.
  - `password` (string, required, min length 8, phức tạp theo yêu cầu): Mật khẩu mới của người dùng.
  - `confirmPassword` (string, required): Phải trùng khớp với `password`.

## 4. Response

**4.1. Thành công:**

- **Status Code:** 200 OK
- \*\*Body (Serialized bởi `BaseResSchema`):
  ```json
  {
    "statusCode": 200,
    "message": "Auth.Password.ResetSuccess" // i18n key
  }
  ```

**4.2. Lỗi:**

- **400 Bad Request (`InvalidVerificationTokenException`, `VerificationTokenExpiredException`, `VerificationTokenAlreadyUsedException`, `UserNotFoundException` (nếu user bị xóa sau khi token được cấp)):**
  - `InvalidVerificationTokenException`: Nếu `verificationToken` không hợp lệ, không tìm thấy, không có `type` là `FORGOT_PASSWORD`, hoặc không có `tokenType` là `VERIFICATION`, hoặc chưa `verified`.
  - `VerificationTokenExpiredException`: Nếu `verificationToken` đã hết hạn.
  - `VerificationTokenAlreadyUsedException`: Nếu `verificationToken` đã được sử dụng để đặt lại mật khẩu trước đó.
  - `UserNotFoundException`: Nếu `userId` liên kết với `verificationToken` không còn tồn tại trong DB.
  ```json
  {
    "type": "https://api.shopsifu.live/errors/bad-request", // Hoặc type cụ thể hơn
    "title": "Bad Request",
    "status": 400,
    "description": "Error.Auth.Token.InvalidVerification", // Hoặc Expired, AlreadyUsed, Error.User.NotFound
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid"
  }
  ```
- **422 Unprocessable Entity (Validation Error):** Nếu request body không hợp lệ (ví dụ: mật khẩu không khớp, `verificationToken` thiếu).
- **500 Internal Server Error (`PasswordUpdateException`):** Nếu có lỗi khi cập nhật mật khẩu người dùng trong DB.

## 5. Luồng Hoạt động (Backend - `AuthService.resetPassword`)

1.  **Validation:** Dữ liệu request (`verificationToken`, `password`, `confirmPassword`) được validate bởi `ResetPasswordBodyDTO` (bao gồm cả việc `password` và `confirmPassword` phải khớp).
2.  **Audit Logging:** Bắt đầu ghi log (`action: 'USER_RESET_PASSWORD_ATTEMPT'`).
3.  **Prisma Transaction:** Các thao tác DB được thực hiện trong một transaction.
4.  **Xác thực `VerificationToken`:**
    - Gọi `AuthRepository.findVerificationToken(body.verificationToken)`.
    - **Nếu không tìm thấy, hoặc `token.type` không phải `FORGOT_PASSWORD`, hoặc `token.tokenType` không phải `VERIFICATION`, hoặc `token.verified` không phải `true`:** Ném `InvalidVerificationTokenException`.
    - **Nếu `token.usedAt` đã có giá trị:** Ném `VerificationTokenAlreadyUsedException`.
    - **Nếu `token.expiresAt` < `new Date()`:** Ném `VerificationTokenExpiredException`.
    - **Nếu `token.userId` không có giá trị:** Ném `InvalidVerificationTokenException` (token quên mật khẩu phải gắn với một user cụ thể).
    - Lấy `userId` và `email` từ `verificationTokenRecord`.
    - Ghi lại `email` và `userId` cho audit log.
5.  **Kiểm tra User:**
    - Gọi `AuthRepository.findUserById(userIdFromToken)`.
    - **Nếu user không tồn tại:** Ném `UserNotFoundException`.
6.  **Hash Mật khẩu Mới:** Gọi `HashingService.hash(body.password)` để hash mật khẩu mới.
7.  **Cập nhật Mật khẩu User:**
    - Gọi `AuthRepository.updateUserPassword(userIdFromToken, hashedPassword)`.
    - **Nếu cập nhật thất bại:** Ném `PasswordUpdateException`.
8.  **Vô hiệu hóa Tất cả `RefreshToken` của User:**
    - Gọi `AuthRepository.deleteAllRefreshTokensByUserId(userIdFromToken)` để xóa tất cả các phiên đăng nhập hiện tại của người dùng trên mọi thiết bị. Đây là một biện pháp bảo mật quan trọng sau khi đặt lại mật khẩu.
9.  **Đánh dấu `VerificationToken` là đã sử dụng:**
    - Cập nhật bản ghi `VerificationToken` (tìm bằng `body.verificationToken`), set `usedAt: new Date()`.
10. **Audit Logging:** Ghi log thành công (`action: 'USER_RESET_PASSWORD_SUCCESS'`).
11. **Trả về Response:** Trả về `{ message: "Auth.Password.ResetSuccess" }`.

## 6. Tương tác FE/BE

1.  **FE:** Sau khi người dùng xác minh OTP cho yêu cầu quên mật khẩu (`POST /auth/verify-code` với `type` là `FORGOT_PASSWORD`) và nhận được `verificationToken` (UUID mới).
    - FE hiển thị form cho người dùng nhập mật khẩu mới và xác nhận mật khẩu mới.
2.  **FE Call API:** Khi người dùng điền đủ thông tin và nhấn "Đặt lại mật khẩu", FE gọi `POST /auth/reset-password` với `verificationToken` (UUID đã lưu), `password`, `confirmPassword`.
3.  **BE:** Xử lý như mục 5.
    - Xác thực `verificationToken`.
    - Cập nhật mật khẩu cho user liên quan.
    - Vô hiệu hóa tất cả refresh token của user đó.
    - Đánh dấu `verificationToken` là đã sử dụng.
    - Trả về message thành công.
4.  **FE:**
    - Nếu BE trả về **200 OK**:
      - Hiển thị thông báo "Đặt lại mật khẩu thành công. Vui lòng đăng nhập bằng mật khẩu mới."
      - Xóa `verificationToken` khỏi state.
      - Chuyển hướng người dùng đến trang đăng nhập.
    - Nếu BE trả về **lỗi** (400 token không hợp lệ/hết hạn/đã dùng, 422 validation, 500...): Hiển thị thông báo lỗi tương ứng. Người dùng có thể cần bắt đầu lại quy trình quên mật khẩu.

## 7. Điểm nổi bật & Lưu ý

- **Ủy quyền bằng `verificationToken`:** Đảm bảo chỉ người dùng đã xác minh quyền sở hữu email mới có thể đặt lại mật khẩu.
- **`verificationToken` chỉ dùng một lần:** Ngăn chặn việc sử dụng lại cùng một token.
- **Vô hiệu hóa Tất cả Phiên đăng nhập:** Một bước bảo mật quan trọng là đăng xuất người dùng khỏi tất cả các thiết bị sau khi mật khẩu được thay đổi, đề phòng trường hợp tài khoản đã bị xâm nhập trước đó.
- **Không Tự động Đăng nhập:** Khác với đăng ký, sau khi đặt lại mật khẩu, người dùng không được tự động đăng nhập. Họ cần đăng nhập lại với mật khẩu mới.
- **Audit Logging:** Ghi lại các nỗ lực và kết quả đặt lại mật khẩu.
