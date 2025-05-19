# Endpoint: `POST /auth/verify-code` - Xác thực mã OTP

## 1. Mô tả

Endpoint này nhận mã OTP (ví dụ: 6 chữ số) mà người dùng nhập, cùng với `otpToken` (UUID) đã được trả về từ endpoint `/auth/send-otp`. Hệ thống sẽ xác thực mã OTP này với bản ghi `VerificationToken` tương ứng trong cơ sở dữ liệu.

Nếu xác thực thành công, `VerificationToken` sẽ được đánh dấu là đã xác minh (`verified: true`) và một `verificationToken` mới (cũng là UUID, nhưng có mục đích khác) sẽ được trả về cho client. `verificationToken` này sẽ được sử dụng trong bước tiếp theo của luồng (ví dụ: hoàn tất đăng ký trong `/auth/register` hoặc đặt lại mật khẩu trong `/auth/reset-password`).

## 2. Decorators

- `@IsPublic()`: Endpoint này công khai.
- `@HttpCode(HttpStatus.OK)`: Trả về HTTP status 200 khi xác thực thành công.
- `@ZodSerializerDto(VerifyOtpResDTO)`: Response trả về sẽ có dạng `VerifyOtpResDTO`.
- `@Throttle({ short: { limit: 5, ttl: 60000 }, medium: { limit: 20, ttl: 300000 } })`: Giới hạn tần suất truy cập để tránh brute-force mã OTP.

## 3. Request

- **Body:** `VerifyOtpBodyDTO`
  ```json
  {
    "otpToken": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", // UUID từ response của /auth/send-otp
    "code": "123456" // Mã OTP 6 chữ số người dùng nhập
  }
  ```
  - `otpToken` (string, required, uuid format): UUID token đã nhận được từ endpoint `/auth/send-otp`.
  - `code` (string, required, length 6): Mã OTP gồm 6 chữ số mà người dùng nhập.

## 4. Response

**4.1. Thành công:**

- **Status Code:** 200 OK
- \*\*Body (Serialized bởi `VerifyOtpResSchema`):
  ```json
  {
    "statusCode": 200,
    "message": "Auth.OTP.VerifiedSuccess", // i18n key
    "data": {
      "message": "Auth.OTP.VerifiedSuccess",
      "verificationToken": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" // UUID token mới cho bước tiếp theo
    }
  }
  ```
  - `verificationToken`: Một UUID token MỚI. Token này xác nhận rằng mã OTP đã được xác minh thành công và sẽ được sử dụng để ủy quyền cho hành động tiếp theo (ví dụ, đăng ký hoặc đặt lại mật khẩu).

**4.2. Lỗi:**

- **400 Bad Request (`InvalidOtpException`, `OtpExpiredException`, `OtpAlreadyVerifiedException`):**
  - `InvalidOtpException`: Nếu `otpToken` (UUID) không tồn tại, hoặc mã `code` (6 chữ số) không khớp với mã đã lưu (sau khi hash).
  - `OtpExpiredException`: Nếu `VerificationToken` (được tìm bằng `otpToken`) đã hết hạn.
  - `OtpAlreadyVerifiedException`: Nếu `VerificationToken` đã được xác minh trước đó (`verified: true`).
  ```json
  {
    "type": "https://api.shopsifu.live/errors/bad-request", // Hoặc một type cụ thể hơn
    "title": "Bad Request",
    "status": 400,
    "description": "Error.Auth.OTP.Invalid", // Hoặc Error.Auth.OTP.Expired, Error.Auth.OTP.AlreadyVerified
    "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
    "requestId": "uuid"
  }
  ```
- **422 Unprocessable Entity (Validation Error):** Nếu request body không hợp lệ (ví dụ: `otpToken` không phải UUID, `code` không phải 6 chữ số).
- **429 Too Many Requests:** Nếu vượt quá giới hạn tần suất.
- **500 Internal Server Error (`VerificationTokenUpdateException`):** Nếu có lỗi khi cập nhật `VerificationToken` trong DB hoặc tạo `verificationToken` mới.

## 5. Luồng Hoạt động (Backend - `AuthService.verifyOtpCode`)

1.  **Validation:** Dữ liệu request (`otpToken`, `code`) được validate bởi `VerifyOtpBodyDTO`.
2.  **Audit Logging:** Bắt đầu ghi log (`action: 'VERIFY_OTP_ATTEMPT'` với `otpToken`).
3.  **Prisma Transaction:** Các thao tác DB được thực hiện trong một transaction.
4.  **Tìm `VerificationToken`:**
    - Gọi `AuthRepository.findVerificationToken(body.otpToken)` để tìm bản ghi `VerificationToken` dựa trên UUID `otpToken` từ request.
    - **Nếu không tìm thấy:** Ném `InvalidOtpException`.
    - Ghi lại `email` và `userId` (nếu có) từ `verificationTokenRecord` cho audit log.
5.  **Kiểm tra Trạng thái Token:**
    - **Nếu `verificationTokenRecord.verified` là `true`:** Ném `OtpAlreadyVerifiedException` (OTP này đã được sử dụng để xác minh rồi).
    - **Nếu `verificationTokenRecord.expiresAt` < `new Date()`:** Ném `OtpExpiredException`.
6.  **Xác thực Mã OTP:**
    - So sánh `body.code` (mã người dùng nhập) với `verificationTokenRecord.code` (mã đã hash trong DB) bằng cách sử dụng `HashingService.compare(body.code, verificationTokenRecord.code)`.
    - **Nếu không khớp:** Ném `InvalidOtpException`.
7.  **Đánh dấu Token là đã Xác minh:**
    - Cập nhật bản ghi `VerificationToken` trong DB: set `verified: true` và `verifiedAt: new Date()` cho bản ghi có `token: body.otpToken`.
    - Nếu cập nhật thất bại, ném `VerificationTokenUpdateException`.
8.  **Tạo `verificationToken` mới cho Bước Tiếp theo:**
    - Tạo một `newVerificationTokenString` (UUID mới).
    - Lưu một bản ghi `VerificationToken` MỚI với các thông tin:
      - `token`: `newVerificationTokenString` (UUID mới).
      - `email`: `verificationTokenRecord.email`.
      - `type`: `verificationTokenRecord.type` (ví dụ: `REGISTER` hoặc `FORGOT_PASSWORD`).
      - `tokenType`: `TokenType.VERIFICATION` (để phân biệt với OTP token ban đầu).
      - `userId`: `verificationTokenRecord.userId` (nếu có).
      - `deviceId`: `verificationTokenRecord.deviceId` (nếu có).
      - `verified`: `true` (token này được coi là đã xác minh ngay từ đầu vì nó chỉ được tạo sau khi OTP thành công).
      - `verifiedAt`: `new Date()`.
      - `expiresAt`: Thời gian hết hạn mới (cấu hình từ `envConfig.VERIFICATION_TOKEN_EXPIRES_IN`).
    - Nếu không lưu được, ném `VerificationTokenUpdateException`.
9.  **Audit Logging:** Ghi log thành công (`action: 'VERIFY_OTP_SUCCESS'`).
10. **Trả về Response:** Trả về `{ message: "Auth.OTP.VerifiedSuccess", verificationToken: newVerificationTokenString }`.

## 6. Tương tác FE/BE

1.  **FE:** Sau khi gọi `/auth/send-otp` thành công và nhận được `otpToken` (UUID), FE hiển thị ô cho người dùng nhập mã OTP 6 chữ số mà họ nhận được qua email.
2.  **FE Call API:** Khi người dùng nhập xong mã OTP và nhấn "Xác nhận", FE gọi `POST /auth/verify-code` với `otpToken` (UUID đã lưu) và `code` (mã 6 chữ số người dùng nhập).
3.  **BE:** Xử lý như mục 5.
    - Xác thực `otpToken` và `code`.
    - Nếu hợp lệ, đánh dấu OTP token cũ là đã xác minh, tạo một `verificationToken` mới (UUID).
    - Trả về `{ verificationToken (UUID mới) }`.
4.  **FE:**
    - Nếu BE trả về **200 OK** với `verificationToken` (UUID mới):
      - Lưu `verificationToken` (UUID mới) này vào state.
      - Xóa `otpToken` (UUID cũ) khỏi state (không cần nữa).
      - **Nếu luồng là Đăng ký (`type` ban đầu là `REGISTER`):** Chuyển người dùng đến trang hoàn tất thông tin đăng ký (tên, mật khẩu), và gửi `verificationToken` này cùng với thông tin đăng ký ở bước `POST /auth/register`.
      - **Nếu luồng là Quên Mật khẩu (`type` ban đầu là `FORGOT_PASSWORD`):** Chuyển người dùng đến trang nhập mật khẩu mới, và gửi `verificationToken` này cùng với mật khẩu mới ở bước `POST /auth/reset-password`.
    - Nếu BE trả về **lỗi** (400 OTP sai/hết hạn/đã dùng, 422, 500...): Hiển thị thông báo lỗi tương ứng. Người dùng có thể cần yêu cầu gửi lại OTP.

## 7. Điểm nổi bật & Lưu ý

- **Hai Loại Token:** Cần phân biệt rõ:
  - `otpToken` (từ `/send-otp`): Liên kết yêu cầu gửi OTP với mã OTP, có thời hạn ngắn, được dùng một lần để xác thực mã.
  - `verificationToken` (từ `/verify-code`): Được cấp SAU KHI OTP thành công, dùng để ủy quyền cho hành động tiếp theo (đăng ký/reset password), có thời hạn riêng (thường dài hơn OTP một chút).
- **OTP Chỉ Dùng Một Lần:** Hệ thống đảm bảo mỗi mã OTP chỉ có thể được xác minh thành công một lần (`OtpAlreadyVerifiedException`).
- **Bảo mật Mã OTP:** Mã OTP được so sánh với bản hash lưu trong DB.
- **Giới hạn Tần suất:** Chống brute-force mã OTP.
- **Audit Logging:** Ghi lại các nỗ lực xác minh OTP.
