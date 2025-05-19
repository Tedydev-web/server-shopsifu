# Endpoint: `POST /auth/refresh-token` - Làm mới Access Token

## 1. Mô tả

Endpoint này được sử dụng để lấy một `accessToken` mới khi `accessToken` hiện tại đã hết hạn. Người dùng gửi `refreshToken` (UUID) mà họ nhận được khi đăng nhập thành công hoặc từ lần làm mới token trước đó. Hệ thống sẽ xác thực `refreshToken`, kiểm tra thiết bị, và nếu hợp lệ, sẽ cấp một cặp `accessToken` và `refreshToken` mới, đồng thời vô hiệu hóa `refreshToken` cũ.

## 2. Decorators

- `@IsPublic()`: Endpoint này không yêu cầu `accessToken` hợp lệ ban đầu, vì mục đích của nó chính là để lấy `accessToken` mới khi cái cũ đã hết hạn. Việc xác thực dựa trên `refreshToken`.
- `@HttpCode(HttpStatus.OK)`: Trả về HTTP status 200 khi thành công.
- `@ZodSerializerDto(RefreshTokenResDTO)`: `RefreshTokenResDTO` (thực chất là `AccessTokenResSchema`) chỉ chứa `accessToken` mới.
- `@Throttle({ medium: { limit: 10, ttl: 60000 } })`: Giới hạn tần suất truy cập.

## 3. Request

- **Body:** `RefreshTokenBodyDTO`
  ```json
  {
    "refreshToken": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" // UUID của Refresh Token
  }
  ```
  - `refreshToken` (string, required, uuid format): Refresh token (UUID) người dùng đang nắm giữ. Backend cũng sẽ kiểm tra cookie `refresh_token` nếu body không cung cấp.
- **Headers (Tự động lấy bởi decorators):**
  - `User-Agent`: Lấy bởi `@UserAgent()` decorator.
  - `Client IP`: Lấy bởi `@Ip()` decorator.
- **Cookies (BE sẽ đọc và ghi đè khi thành công):**
  - BE sẽ đọc `refresh_token` từ cookie nếu không có trong body.
  - BE sẽ thiết lập `access_token` (mới) và `refresh_token` (mới) vào cookies khi thành công.

## 4. Response

**4.1. Thành công:**

- **Status Code:** 200 OK
- **Body (Serialized bởi `AccessTokenResSchema`):**
  ```json
  {
    "statusCode": 200,
    "message": "Global.Success", // Hoặc một message key cụ thể hơn
    "data": {
      "accessToken": "new_jwt_access_token"
    }
  }
  ```
- **Cookies được thiết lập/ghi đè:**
  - `access_token`: Chứa JWT Access Token MỚI.
  - `refresh_token`: Chứa JWT Refresh Token (UUID) MỚI.

**4.2. Lỗi:**

- **401 Unauthorized (`UnauthorizedAccessException`, `DeviceMismatchException`, `InvalidDeviceException`):**
  - Nếu không có `refreshToken` nào được cung cấp (cả trong body và cookie).
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
  - Nếu `refreshToken` không hợp lệ, không tìm thấy trong DB, đã được sử dụng, hoặc đã hết hạn.
    - Nếu token có dấu hiệu bị sử dụng lại (replay attack), tất cả các refresh token của user đó sẽ bị vô hiệu hóa.
  - Nếu `refreshToken` không có `deviceId` liên kết.
  - Nếu `userAgent` hoặc `ip` không khớp với thông tin thiết bị được lưu trữ (`DeviceMismatchException`). Trong trường hợp này, tất cả các refresh token của user cũng sẽ bị vô hiệu hóa.
    ```json
    {
      "type": "https://api.shopsifu.live/errors/authentication-failure", // or specific device error
      "title": "Unauthorized",
      "status": 401,
      "description": "Error.Auth.Device.Mismatch",
      "timestamp": "YYYY-MM-DDTHH:mm:ss.sssZ",
      "requestId": "uuid"
    }
    ```
- **422 Unprocessable Entity (Validation Error):** Nếu `refreshToken` trong body không phải là UUID hợp lệ.
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
        "field": "refreshToken",
        "description": "Error.Validation.refreshToken.invalid_string" // Key i18n từ Zod
      }
    ]
  }
  ```
- **429 Too Many Requests:** Nếu vượt quá giới hạn tần suất.

## 5. Luồng Hoạt động (Backend - `AuthService.refreshToken`)

1.  **Validation:** Dữ liệu request body (`refreshToken`) được validate bởi `RefreshTokenBodyDTO`.
2.  **Audit Logging:** Bắt đầu ghi log (`action: 'REFRESH_TOKEN_ATTEMPT'`).
3.  **Prisma Transaction:** Các thao tác DB được thực hiện trong một transaction.
4.  **Lấy Refresh Token:**
    - Ưu tiên lấy `refreshToken` từ `body.refreshToken`.
    - Nếu không có, thử lấy từ `req.cookies[CookieNames.REFRESH_TOKEN]`.
    - Nếu không tìm thấy ở cả hai nơi, ném `UnauthorizedAccessException` (hoặc một lỗi cụ thể hơn như `MissingRefreshTokenException` nếu được định nghĩa).
5.  **Xác thực Refresh Token (UUID):**
    - Tìm `refreshToken` (UUID) trong bảng `RefreshToken`. Query cũng bao gồm thông tin `user` (và `role` của user) và `device` liên quan.
    - **Nếu không tìm thấy `refreshToken` HOẶC `refreshToken` không có user liên kết:**
      - Thực hiện kiểm tra xem token này có dấu hiệu bị sử dụng lại không (ví dụ, tìm token chỉ dựa trên chuỗi UUID để xem nó có `used: true` hoặc đã hết hạn không).
      - **Nếu có dấu hiệu replayed/expired token:** Vô hiệu hóa TẤT CẢ các `RefreshToken` của `userId` liên quan (nếu `userId` có thể xác định được từ token đã dùng/hết hạn đó) bằng cách xóa chúng khỏi DB. Đây là một biện pháp an ninh để chống lại việc token bị đánh cắp và sử dụng lại.
      - Xóa cookies token trên client (nếu có `res` object).
      - Ném `UnauthorizedAccessException`.
    - Ghi lại `userId` và `userEmail` cho audit log.
6.  **Đánh dấu Refresh Token cũ là đã sử dụng:** Cập nhật bản ghi `RefreshToken` cũ trong DB, set `used: true`.
    - Nếu `refreshToken` đột ngột biến mất (ví dụ, bị xóa bởi một tiến trình khác) trước khi có thể đánh dấu là đã dùng, ném `UnauthorizedAccessException`.
7.  **Xác thực Thiết bị (`Device`):**
    - Lấy thông tin `device` từ `existingRefreshToken.device`.
    - **Nếu không có `device` liên kết với `refreshToken`:** Vô hiệu hóa tất cả refresh token của user và ném `InvalidDeviceException`.
    - **Nếu có `device`:** Gọi `AuthRepository.validateDevice` với `deviceId`, `userAgent` (từ request), `ip` (từ request).
      - `validateDevice` kiểm tra `device.isActive` và so sánh `device.userAgent` với `userAgent` từ request. Nó cũng cập nhật `lastActive` và `ip` của device.
      - **Nếu `validateDevice` trả về `false` (không hợp lệ):**
        - Vô hiệu hóa TẤT CẢ các `RefreshToken` của `userId` đó.
        - Xóa cookies token trên client.
        - Ném `DeviceMismatchException`.
      - Nếu hợp lệ, `currentDeviceId` được xác định.
8.  **Kiểm tra `currentDeviceId`:** Đảm bảo `currentDeviceId` có giá trị sau bước xác thực thiết bị.
9.  **Tạo Cặp Token Mới:** Gọi `AuthService.generateTokens` với `userId`, `currentDeviceId`, `roleId`, `roleName` của user, và `existingRefreshToken.rememberMe` (để quyết định thời gian sống của refresh token mới).
    - `generateTokens` sẽ tạo ra `newAccessToken` (JWT) và `newRefreshTokenString` (UUID mới), cùng với `maxAgeForRefreshTokenCookie`.
10. **Thiết lập Cookies Mới:** Nếu có `res` object, gọi `TokenService.setTokenCookies` để thiết lập `access_token` (mới) và `refresh_token` (mới) vào HTTP response cookies với `maxAgeForRefreshTokenCookie` tương ứng.
11. **Audit Logging:** Ghi log thành công (`action: 'REFRESH_TOKEN_SUCCESS'`).
12. **Trả về Response:** Trả về `{ accessToken: newAccessToken }`.

## 6. Tương tác FE/BE

1.  **FE:** Khi `accessToken` hết hạn (ví dụ: API trả về lỗi 401 `ExpiredAccessTokenException`), interceptor của FE (hoặc logic xử lý lỗi) sẽ tự động gọi API `POST /auth/refresh-token`.
    - FE có thể gửi `refreshToken` từ cookie (nếu BE cấu hình đọc từ cookie) hoặc từ một nơi lưu trữ an toàn trong FE (ít phổ biến hơn và không khuyến khích cho web nếu dùng HttpOnly cookie).
    - Trong hệ thống này, BE ưu tiên đọc `refreshToken` từ body, sau đó mới đến cookie. FE nên gửi `refreshToken` lấy từ cookie `refresh_token` vào body của request này.
2.  **BE:** Xử lý như mô tả ở mục 5.
3.  **FE:**
    - **Nếu BE trả về `accessToken` mới (200 OK):**
      - FE cập nhật `accessToken` mới này vào state/bộ nhớ của nó.
      - Cookies `access_token` (mới) và `refresh_token` (mới) đã được BE tự động thiết lập/ghi đè.
      - FE tự động thực hiện lại yêu cầu API ban đầu (mà đã thất bại do token hết hạn) với `accessToken` mới.
    - **Nếu BE trả về lỗi (ví dụ: 401):**
      - Điều này có nghĩa là `refreshToken` cũng không hợp lệ (hết hạn, bị thu hồi, thiết bị không khớp...).
      - FE nên xóa mọi thông tin xác thực đã lưu (user state, token...).
      - Chuyển hướng người dùng về trang đăng nhập.
      - Hiển thị thông báo yêu cầu đăng nhập lại.

## 7. Điểm nổi bật & Lưu ý

- **Refresh Token Rotation:** Hệ thống áp dụng cơ chế xoay vòng refresh token. Mỗi lần refresh token được sử dụng thành công, một refresh token MỚI sẽ được cấp và refresh token CŨ sẽ bị đánh dấu là đã sử dụng (hoặc vô hiệu hóa). Điều này giúp giảm thiểu rủi ro nếu một refresh token bị lộ, vì nó chỉ có thể được sử dụng một lần.
- **Phát hiện Replay Attack:** Nếu một refresh token đã được sử dụng (hoặc hết hạn) được gửi lại, hệ thống sẽ coi đó là dấu hiệu của một cuộc tấn công tiềm tàng (replay attack) và sẽ vô hiệu hóa tất cả các refresh token của người dùng đó như một biện pháp phòng ngừa.
- **Xác thực Thiết bị:** Việc kiểm tra `userAgent` và `ip` khi làm mới token giúp phát hiện nếu refresh token bị đánh cắp và sử dụng trên một thiết bị hoàn toàn khác.
- **Cookie Handling:** BE tự động quản lý việc đọc và ghi đè cookies `access_token` và `refresh_token`.
- **Audit Logging:** Mọi nỗ lực làm mới token đều được ghi log.
