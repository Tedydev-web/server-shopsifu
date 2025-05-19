# Endpoint: `POST /auth/logout` - Đăng xuất tài khoản

## 1. Mô tả

Endpoint này cho phép người dùng đăng xuất khỏi hệ thống. Khi được gọi, nó sẽ vô hiệu hóa `refreshToken` hiện tại của người dùng (nếu có) và xóa các cookie `access_token` và `refresh_token` khỏi trình duyệt của người dùng.

## 2. Decorators

- `@UseGuards(AccessTokenGuard)`: Yêu cầu `accessToken` hợp lệ để truy cập endpoint này. Điều này đảm bảo chỉ người dùng đã đăng nhập mới có thể đăng xuất.
- `@HttpCode(HttpStatus.OK)`: Trả về HTTP status 200 khi đăng xuất thành công.
- `@ZodSerializerDto(LogoutResDTO)`: Response trả về sẽ có dạng `LogoutResDTO` (chỉ chứa message thành công).
- `@Throttle({ short: { limit: 5, ttl: 60000 } })`: Giới hạn tần suất truy cập.

## 3. Request

- **Body:** `LogoutBodyDTO` (có thể là rỗng hoặc chứa `everywhere`)

  ```json
  // Đăng xuất khỏi thiết bị hiện tại (mặc định)
  {}

  // Hoặc đăng xuất khỏi tất cả thiết bị
  {
    "everywhere": true
  }
  ```

  - `everywhere` (boolean, optional, default: `false`): Nếu `true`, tất cả các `refreshToken` của người dùng trên mọi thiết bị sẽ bị vô hiệu hóa. Nếu `false` hoặc không được cung cấp, chỉ `refreshToken` liên quan đến thiết bị hiện tại (thông qua cookie) sẽ bị vô hiệu hóa.

- **Cookies (BE sẽ đọc và xóa):**
  - `access_token`: Đọc để xác thực người dùng.
  - `refresh_token`: Đọc để tìm và vô hiệu hóa token tương ứng.
  - BE sẽ xóa cả hai cookie này khi đăng xuất thành công.
- **Headers (Tự động lấy bởi Guards/Decorators):**
  - `Authorization: Bearer <access_token>`: Được xử lý bởi `AccessTokenGuard`.

## 4. Response

**4.1. Thành công:**

- **Status Code:** 200 OK
- \*\*Body (Serialized bởi `LogoutResSchema`):
  ```json
  {
    "statusCode": 200,
    "message": "Auth.Logout.Success",
    "data": {
      "message": "Auth.Logout.Success"
    }
  }
  ```
- **Cookies bị xóa:**
  - `access_token`
  - `refresh_token`

**4.2. Lỗi:**

- **401 Unauthorized (`UnauthorizedAccessException`):**
  - Nếu `accessToken` không hợp lệ hoặc hết hạn (xử lý bởi `AccessTokenGuard`).
  - Nếu không tìm thấy `refreshToken` trong cookie (trường hợp `everywhere: false`).
    ```json
    {
      "type": "https://api.shopsifu.live/errors/unauthenticated",
      "title": "Unauthorized",
      "status": 401,
      "description": "Error.Auth.Access.Unauthorized", // Hoặc Error.Auth.Token.MissingRefreshToken
      "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
      "requestId": "uuid"
    }
    ```
- **422 Unprocessable Entity (Validation Error):** Nếu `everywhere` trong body không phải là boolean.
- **429 Too Many Requests:** Nếu vượt quá giới hạn tần suất.

## 5. Luồng Hoạt động (Backend - `AuthService.logout`)

1.  **Xác thực:** `AccessTokenGuard` kiểm tra tính hợp lệ của `accessToken` từ header.
2.  **Lấy User ID:** Thông tin người dùng (`userId`) được trích xuất từ payload của `accessToken` (thông qua `req.user`).
3.  **Audit Logging:** Bắt đầu ghi log (`action: 'USER_LOGOUT_ATTEMPT'`).
4.  **Lấy `refreshTokenString` từ Cookie:**
    - Đọc giá trị của cookie `refresh_token` (`req.cookies[CookieNames.REFRESH_TOKEN]`).
5.  **Xử lý dựa trên `body.everywhere`:**
    - **Nếu `body.everywhere` là `true`:**
      a. Gọi `AuthRepository.deleteAllRefreshTokensByUserId(userId)` để xóa tất cả các bản ghi `RefreshToken` liên quan đến `userId` này khỏi DB.
      b. Ghi chú vào audit log "Logged out from all devices".
    - **Nếu `body.everywhere` là `false` hoặc không được cung cấp:**
      a. **Nếu không có `refreshTokenString` từ cookie:** Ném `UnauthorizedAccessException` (vì không có token cụ thể nào để vô hiệu hóa cho thiết bị này).
      b. **Nếu có `refreshTokenString`:** Gọi `AuthRepository.deleteRefreshToken(refreshTokenString)` để xóa bản ghi `RefreshToken` cụ thể này khỏi DB.
      c. Ghi chú vào audit log "Logged out from current device".
6.  **Xóa Cookies:** Nếu có `res` object, gọi `TokenService.clearTokenCookies(res)` để gửi lệnh xóa cookies `access_token` và `refresh_token` về phía client.
7.  **Audit Logging:** Ghi log thành công (`action: 'USER_LOGOUT_SUCCESS'`).
8.  **Trả về Response:** Trả về `{ message: "Auth.Logout.Success" }`.

## 6. Tương tác FE/BE

1.  **FE:** Người dùng nhấp vào nút "Đăng xuất".
2.  **FE Call API:** `POST /auth/logout` (có thể kèm body `{ "everywhere": true }` nếu người dùng chọn đăng xuất khỏi tất cả thiết bị).
    - `accessToken` sẽ tự động được gửi kèm trong header `Authorization` bởi HTTP client (nếu đã cấu hình interceptor).
3.  **BE:** Xử lý như mô tả ở mục 5.
4.  **FE:**
    - **Nếu BE trả về 200 OK:**
      - Đăng xuất thành công.
      - FE xóa mọi thông tin xác thực đã lưu (user state, token trong bộ nhớ nếu có).
      - Cookies `access_token` và `refresh_token` đã được BE gửi lệnh xóa.
      - Chuyển hướng người dùng về trang đăng nhập hoặc trang chủ công khai.
    - **Nếu BE trả về lỗi (ví dụ: 401 do token hết hạn trước khi gọi logout):**
      - FE vẫn nên xử lý như trường hợp thành công: xóa state, chuyển hướng về trang đăng nhập. Lỗi này thường không ảnh hưởng đến hành động cuối cùng của người dùng là muốn đăng xuất.

## 7. Điểm nổi bật & Lưu ý

- **Bắt buộc `AccessTokenGuard`:** Đảm bảo chỉ người dùng đã đăng nhập mới có thể thực hiện hành động đăng xuất.
- **Tùy chọn `everywhere`:** Cung cấp sự linh hoạt cho người dùng để đăng xuất khỏi thiết bị hiện tại hoặc tất cả các thiết bị đang hoạt động.
- **Xóa Cookie An Toàn:** Việc xóa cookie được thực hiện bởi BE thông qua việc gửi header `Set-Cookie` với `Max-Age=0` hoặc ngày hết hạn trong quá khứ.
- **Vô hiệu hóa Refresh Token:** Quan trọng là không chỉ xóa cookie mà còn phải vô hiệu hóa (xóa) `refreshToken` trong cơ sở dữ liệu để ngăn chặn việc sử dụng lại nếu nó đã bị lộ trước đó.
- **Audit Logging:** Ghi lại hành động đăng xuất.
