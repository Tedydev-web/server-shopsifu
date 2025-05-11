Dựa trên yêu cầu của bạn và schema Prisma hiện tại, tôi sẽ thiết kế bảng `OtpToken` một cách **chuẩn nhất**, **tối ưu nhất**, **đầy đủ nhất**, và tuân theo **best practices** để hỗ trợ flow xác thực OTP và reset password. Tôi cũng sẽ giải thích lý do tại sao các trường như `deviceId` và `userId` có thể cần thiết hoặc không, đồng thời cập nhật API specification để tích hợp endpoint `/auth/verify-code` riêng biệt, tách khỏi `/auth/register` và `/auth/reset-password`.

---

### **Phân tích yêu cầu**
1. **Hiện tại:**
   - Bạn đã có bảng `VerificationCode` để lưu OTP với các trường: `email`, `code`, `type` (REGISTER hoặc FORGOT_PASSWORD), và `expiresAt`.
   - OTP được verify trực tiếp trong các endpoint `/auth/register` và `/auth/reset-password`, nhưng bạn muốn tách logic verify OTP ra endpoint riêng `/auth/verify-code`.
   - Bạn muốn thiết kế bảng `OtpToken` tương tự `RefreshToken`, nhưng cần đánh giá xem các trường như `deviceId` và `userId` có cần thiết không.

2. **Mục tiêu:**
   - Thiết kế bảng `OtpToken` để lưu trữ token được cấp sau khi verify OTP thành công, dùng cho các bước tiếp theo (đăng ký hoặc reset password).
   - Đảm bảo bảng này hỗ trợ flow mới với endpoint `/auth/verify-code`.
   - Tối ưu bảo mật, hiệu suất, và khả năng mở rộng.
   - Giải thích việc sử dụng `deviceId` và `userId` trong bối cảnh OTP và reset password.

3. **Flow mong muốn:**
   - Người dùng gửi OTP qua `/auth/otp` với `email` và `type` (REGISTER hoặc FORGOT_PASSWORD).
   - Người dùng verify OTP qua `/auth/verify-code`.
   - Nếu verify thành công, backend trả về một `otpToken` (tương tự refresh token), được sử dụng trong các endpoint `/auth/register` hoặc `/auth/reset-password`.

---

### **Thiết kế bảng `OtpToken`**

Dựa trên schema hiện tại, tôi đề xuất thêm bảng `OtpToken` vào schema Prisma với các trường được thiết kế để tối ưu hóa bảo mật, hiệu suất, và khả năng mở rộng. Dưới đây là thiết kế chi tiết:

#### **Schema Prisma cho `OtpToken`**
```prisma
model OtpToken {
  id        Int      @id @default(autoincrement())
  token     String   @unique @db.VarChar(1000) // Token duy nhất (UUID)
  userId    Int?     // Liên kết với User (nullable vì REGISTER có thể chưa có user)
  user      User?    @relation(fields: [userId], references: [id], onDelete: Cascade, onUpdate: NoAction)
  email     String   @db.VarChar(500) // Email liên kết với token
  deviceId  Int?     // Liên kết với Device (nullable để hỗ trợ trường hợp chưa có device)
  device    Device?  @relation(fields: [deviceId], references: [id], onDelete: Cascade, onUpdate: NoAction)
  type      VerificationCodeType // REGISTER hoặc FORGOT_PASSWORD
  expiresAt DateTime // Thời gian hết hạn (ví dụ: 15 phút)
  createdAt DateTime @default(now())
  usedAt    DateTime? // Thời gian token được sử dụng (để ngăn tái sử dụng)

  @@index([expiresAt])
  @@index([email, type])
}
```

#### **Giải thích các trường**
1. **`id`**:  
   - Khóa chính tự tăng để đảm bảo mỗi token có ID duy nhất.
   - Hỗ trợ truy vấn nhanh và quản lý dễ dàng.

2. **`token`**:  
   - Chuỗi duy nhất (UUID) để xác định token.
   - Được tạo ngẫu nhiên và đảm bảo không thể đoán trước.
   - Độ dài tối đa 1000 ký tự để hỗ trợ JWT nếu cần.

3. **`userId`** (nullable):  
   - Liên kết với bảng `User` để gắn token với người dùng.
   - Nullable vì trong trường hợp `REGISTER`, tài khoản chưa được tạo (chưa có `userId`).
   - Trong trường hợp `FORGOT_PASSWORD`, `userId` có thể được điền nếu email đã tồn tại trong bảng `User`.
   - **Lý do cần thiết:**  
     - Giúp theo dõi token thuộc về ai, đặc biệt trong trường hợp reset password.
     - Hỗ trợ kiểm tra quyền truy cập (ví dụ: chỉ người dùng có `userId` hợp lệ mới được reset password).
     - Nếu không dùng `userId`, bạn vẫn có thể dựa vào `email`, nhưng `userId` cung cấp thêm một lớp xác thực.

4. **`email`**:  
   - Lưu email liên kết với token để đảm bảo token chỉ được sử dụng cho email đã yêu cầu OTP.
   - Dùng làm khóa phụ để truy vấn nhanh (kết hợp với `type` trong index).

5. **`deviceId`** (nullable):  
   - Liên kết với bảng `Device` để gắn token với thiết bị cụ thể.
   - Nullable vì trong một số trường hợp (như đăng ký lần đầu), thiết bị có thể chưa được lưu vào bảng `Device`.
   - **Lý do cần thiết (tùy trường hợp):**  
     - Tăng bảo mật bằng cách giới hạn token chỉ hợp lệ trên thiết bị đã yêu cầu OTP.
     - Hỗ trợ theo dõi thiết bị (ví dụ: phát hiện đăng nhập từ thiết bị lạ).
     - Tuy nhiên, nếu bạn muốn đơn giản hóa, có thể bỏ `deviceId` và chỉ dựa vào `ip` hoặc `userAgent` lưu trong bảng `OtpToken` (như đề xuất dưới).

6. **`type`**:  
   - Enum `VerificationCodeType` (REGISTER hoặc FORGOT_PASSWORD) để xác định mục đích của token.
   - Giúp backend xử lý logic khác nhau tùy theo loại token.

7. **`expiresAt`**:  
   - Thời gian hết hạn của token (ví dụ: 15 phút).
   - Được index để tối ưu truy vấn khi kiểm tra token còn hiệu lực.

8. **`createdAt`**:  
   - Thời gian tạo token để theo dõi và audit.

9. **`usedAt`** (nullable):  
   - Thời gian token được sử dụng (để reset password hoặc đăng ký).
   - Đảm bảo token chỉ được sử dụng một lần (nếu `usedAt` đã có giá trị, token không hợp lệ nữa).

10. **Indexes**:  
    - `@@index([expiresAt])`: Tối ưu truy vấn các token còn hiệu lực.
    - `@@index([email, type])`: Tăng tốc độ tìm kiếm token theo email và loại.

#### **So sánh với `RefreshToken`**
- **Giống nhau:**  
  - Cả `OtpToken` và `RefreshToken` đều lưu trữ token tạm thời, có thời hạn (`expiresAt`), và liên kết với người dùng (`userId`).
  - Cả hai đều có thể gắn với thiết bị (`deviceId`).
- **Khác nhau:**  
  - `OtpToken` có `type` để phân biệt REGISTER và FORGOT_PASSWORD, trong khi `RefreshToken` chỉ dùng cho xác thực phiên.
  - `OtpToken` cần hỗ trợ trường hợp chưa có `userId` (cho REGISTER), trong khi `RefreshToken` luôn yêu cầu `userId`.
  - `OtpToken` có `usedAt` để đảm bảo chỉ sử dụng một lần, trong khi `RefreshToken` có thể được sử dụng nhiều lần trong thời gian hiệu lực.

#### **Có cần `deviceId` và `userId` không?**
- **`deviceId`:**  
  - **Nên có** nếu bạn muốn tăng bảo mật bằng cách giới hạn token chỉ hợp lệ trên thiết bị đã yêu cầu OTP. Điều này đặc biệt quan trọng trong trường hợp reset password, nơi kẻ tấn công có thể cố sử dụng token bị lộ từ thiết bị khác.
  - **Có thể bỏ** nếu bạn muốn đơn giản hóa và không muốn lưu thông tin thiết bị. Thay vào đó, bạn có thể thêm trường `ip` và `userAgent` trực tiếp vào `OtpToken`:
    ```prisma
    ip        String? @db.VarChar(100)
    userAgent String? @db.VarChar(1000)
    ```
    - Khi verify token, backend kiểm tra xem `ip` và `userAgent` có khớp với request ban đầu không.

- **`userId`:**  
  - **Nên có** vì nó giúp liên kết token với người dùng cụ thể, đặc biệt trong trường hợp reset password. Điều này đảm bảo rằng chỉ người dùng hợp lệ mới có thể sử dụng token.
  - **Nullable** để hỗ trợ trường hợp REGISTER, khi tài khoản chưa được tạo.
  - Nếu bạn không muốn dùng `userId`, bạn có thể dựa hoàn toàn vào `email`, nhưng điều này kém an toàn hơn vì email không phải là khóa chính duy nhất (có thể bị giả mạo nếu không có kiểm tra bổ sung).

---

### **Flow tích hợp với endpoint `/auth/verify-code`**

Dưới đây là flow mới với endpoint `/auth/verify-code` riêng biệt:

1. **Gửi OTP (`/auth/otp`):**
   - Request:
     ```json
     {
         "email": "hieudat2310.bh@gmail.com",
         "type": "REGISTER" // hoặc "FORGOT_PASSWORD"
     }
     ```
   - Backend:
     - Tạo OTP và lưu vào bảng `VerificationCode` với `email`, `code`, `type`, và `expiresAt`.
     - Lưu thêm `ip` và `userAgent` nếu không dùng `deviceId`.
     - Trả về: `{ "message": "OTP sent to email" }`.

2. **Xác thực OTP (`/auth/verify-code`):**
   - Request:
     ```json
     {
         "email": "hieudat2310.bh@gmail.com",
         "code": "992387",
         "type": "REGISTER" // hoặc "FORGOT_PASSWORD"
     }
     ```
   - Backend:
     - Kiểm tra OTP trong bảng `VerificationCode`:
       - Xác minh `email`, `code`, và `type` khớp, và `expiresAt` chưa qua.
       - Nếu hợp lệ, xóa OTP hoặc đánh dấu là đã sử dụng.
     - Tạo một `OtpToken` mới:
       - `token`: UUID.
       - `email`: Từ request.
       - `userId`: Nếu `type` là FORGOT_PASSWORD và email tồn tại trong bảng `User`, lấy `userId`.
       - `deviceId`: Nếu có thông tin thiết bị trong bảng `Device`.
       - `type`: REGISTER hoặc FORGOT_PASSWORD.
       - `expiresAt`: 15 phút sau.
       - `ip` và `userAgent` (nếu không dùng `deviceId`).
     - Trả về:
       ```json
       {
           "otpToken": "abc123xyz"
       }
       ```
   - Frontend:
     - Lưu `otpToken` vào `sessionStorage`.
     - Chuyển hướng đến UI đăng ký (`/register`) hoặc reset password (`/reset-password`).

3. **Đăng ký (`/auth/register`):**
   - Request:
     ```json
     {
         "otpToken": "abc123xyz",
         "email": "hieudat2310.bh@gmail.com",
         "name": "Hieu Dat",
         "phoneNumber": "0123456789",
         "password": "{{defaultPwd}}",
         "confirmPassword": "{{defaultPwd}}"
     }
     ```
   - Backend:
     - Kiểm tra `otpToken` trong bảng `OtpToken`:
       - Xác minh `token`, `email`, `type` (REGISTER), và `expiresAt` chưa qua.
       - Kiểm tra `usedAt` là null (chưa sử dụng).
       - Nếu có `deviceId` hoặc `ip`/`userAgent`, kiểm tra khớp với request.
     - Nếu hợp lệ:
       - Tạo tài khoản mới trong bảng `User`.
       - Đánh dấu `usedAt` cho `OtpToken` hoặc xóa token.
     - Trả về: `{ "message": "Registration successful" }`.

4. **Reset password (`/auth/reset-password`):**
   - Request:
     ```json
     {
         "otpToken": "abc123xyz",
         "email": "hieudat2310.bh@gmail.com",
         "newPassword": "{{defaultPwd}}",
         "confirmNewPassword": "{{defaultPwd}}"
     }
     ```
   - Backend:
     - Kiểm tra `otpToken` trong bảng `OtpToken`:
       - Xác minh `token`, `email`, `type` (FORGOT_PASSWORD), và `expiresAt` chưa qua.
       - Kiểm tra `usedAt` là null.
       - Nếu có `userId`, đảm bảo `email` khớp với `User.email`.
       - Nếu có `deviceId` hoặc `ip`/`userAgent`, kiểm tra khớp với request.
     - Nếu hợp lệ:
       - Cập nhật `password` trong bảng `User`.
       - Đánh dấu `usedAt` cho `OtpToken` hoặc xóa token.
       - Gửi email thông báo: "Mật khẩu của bạn đã được thay đổi."
     - Trả về: `{ "message": "Password reset successfully" }`.

---

### **Tại sao thiết kế này là best practices?**
1. **Bảo mật:**
   - `OtpToken` được gắn với `email`, `userId` (nếu có), và `deviceId`/`ip`/`userAgent` để ngăn sử dụng token trên thiết bị khác.
   - Token chỉ sử dụng một lần (`usedAt`) và có thời hạn ngắn (15 phút).
   - Tách logic verify OTP ra endpoint riêng giảm nguy cơ lộ OTP trong các endpoint khác.

2. **Tối ưu hiệu suất:**
   - Indexes trên `expiresAt` và `email, type` đảm bảo truy vấn nhanh.
   - Sử dụng `userId` và `deviceId` tận dụng các mối quan hệ có sẵn trong schema.

3. **Khả năng mở rộng:**
   - Hỗ trợ nhiều loại OTP (REGISTER, FORGOT_PASSWORD, LOGIN, DISABLE_2FA) thông qua `type`.
   - Dễ dàng thêm các trường như `ip` hoặc `userAgent` nếu cần tăng bảo mật.

4. **Tính linh hoạt:**
   - Nullable `userId` và `deviceId` hỗ trợ cả trường hợp chưa có tài khoản (REGISTER) và đã có tài khoản (FORGOT_PASSWORD).
   - Có thể tích hợp với 2FA hoặc các cơ chế xác thực bổ sung.

---

### **API Specification cập nhật**

Dưới đây là artifact cập nhật, bao gồm endpoint `/auth/verify-code` và tích hợp `OtpToken`:


# API Specification for Authentication Flow

## 1. Send OTP API
- **Endpoint:** `POST /auth/otp`
- **Request Body:**
  ```json
  {
      "email": "hieudat2310.bh@gmail.com",
      "type": "REGISTER" // hoặc "FORGOT_PASSWORD"
  }
  ```
- **Response:**
  ```json
  {
      "message": "OTP sent to email"
  }
  ```
- **Security Notes:**
  - Lưu OTP vào bảng `VerificationCode` với `email`, `code`, `type`, và `expiresAt` (10 phút).
  - Lưu `ip` và `userAgent` để kiểm tra khi verify.
  - Giới hạn 5 lần gửi OTP/giờ cho mỗi email.

## 2. Verify OTP API
- **Endpoint:** `POST /auth/verify-code`
- **Request Body:**
  ```json
  {
      "email": "hieudat2310.bh@gmail.com",
      "code": "992387",
      "type": "REGISTER" // hoặc "FORGOT_PASSWORD"
  }
  ```
- **Response:**
  ```json
  {
      "otpToken": "abc123xyz"
  }
  ```
- **Security Notes:**
  - Kiểm tra OTP trong bảng `VerificationCode`: `email`, `code`, `type`, và `expiresAt`.
  - Nếu hợp lệ, xóa OTP và tạo `OtpToken` với `token`, `email`, `userId` (nếu có), `deviceId` (nếu có), `type`, `expiresAt` (15 phút).
  - Lưu `ip` và `userAgent` trong `OtpToken` nếu không dùng `deviceId`.
  - Frontend lưu `otpToken` vào `sessionStorage` và chuyển hướng đến `/register` hoặc `/reset-password`.

## 3. Register API
- **Endpoint:** `POST /auth/register`
- **Request Body:**
  ```json
  {
      "otpToken": "abc123xyz",
      "email": "hieudat2310.bh@gmail.com",
      "name": "Hieu Dat",
      "phoneNumber": "0123456789",
      "password": "{{defaultPwd}}",
      "confirmPassword": "{{defaultPwd}}"
  }
  ```
- **Response:**
  ```json
  {
      "message": "Registration successful"
  }
  ```
- **Security Notes:**
  - Kiểm tra `otpToken` trong bảng `OtpToken`: `token`, `email`, `type` (REGISTER), `expiresAt`, và `usedAt` (null).
  - Kiểm tra `ip` và `userAgent` hoặc `deviceId` khớp với request.
  - Tạo tài khoản trong bảng `User`.
  - Đánh dấu `usedAt` cho `OtpToken` hoặc xóa token.
  - Frontend xóa `otpToken` khỏi `sessionStorage`.

## 4. Reset Password API
- **Endpoint:** `POST /auth/reset-password`
- **Request Body:**
  ```json
  {
      "otpToken": "abc123xyz",
      "email": "hieudat2310.bh@gmail.com",
      "newPassword": "{{defaultPwd}}",
      "confirmNewPassword": "{{defaultPwd}}"
  }
  ```
- **Response:**
  ```json
  {
      "message": "Password reset successfully"
  }
  ```
- **Security Notes:**
  - Kiểm tra `otpToken` trong bảng `OtpToken`: `token`, `email`, `type` (FORGOT_PASSWORD), `expiresAt`, và `usedAt` (null).
  - Kiểm tra `userId` (nếu có) và `email` khớp với bảng `User`.
  - Kiểm tra `ip` và `userAgent` hoặc `deviceId` khớp với request.
  - Cập nhật `password` trong bảng `User`.
  - Đánh dấu `usedAt` cho `OtpToken` hoặc xóa token.
  - Gửi email thông báo: "Mật khẩu của bạn đã được thay đổi."
  - Frontend xóa `otpToken` khỏi `sessionStorage`.


---



### **Kết luận**
- Bảng `OtpToken` được thiết kế với các trường `token`, `userId` (nullable), `email`, `deviceId` (nullable), `type`, `expiresAt`, và `usedAt`, đảm bảo **bảo mật**, **hiệu suất**, và **khả năng mở rộng**.
- Việc sử dụng `userId` và `deviceId` tăng cường bảo mật bằng cách gắn token với người dùng và thiết bị, nhưng có thể thay bằng `ip` và `userAgent` nếu muốn đơn giản hóa.
- Endpoint `/auth/verify-code` tách biệt logic verify OTP, giúp flow rõ ràng và an toàn hơn.
- Artifact được cập nhật để phản ánh flow mới và tích hợp `OtpToken`, giữ nguyên `artifact_id` để duy trì tính liên tục.