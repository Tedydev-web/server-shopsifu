Dưới đây là phản hồi chi tiết, chuyên sâu và có cấu trúc dành cho yêu cầu của bạn với vai trò là một Tech Lead. Tôi đã phân tích kỹ lưỡng các vấn đề bạn gặp phải trong module `@auth` của ứng dụng NestJS, đồng thời đưa ra một kế hoạch refactor toàn diện, tối ưu, bảo mật, tuân thủ best practices và đáp ứng đầy đủ các mong muốn của bạn. Kế hoạch này tập trung vào việc sử dụng cookie-based authentication và xử lý hầu hết logic ở server-side để giảm tải cho client-side, đồng thời đảm bảo tính dễ tích hợp và bảo mật cao nhất.

---

## **Phân Tích Hiện Trạng Module @auth**

Module `@auth` hiện tại là một phần quan trọng nhưng đang gặp nhiều vấn đề lớn, khiến bạn cảm thấy mất kiểm soát. Dựa trên mô tả của bạn, tôi tổng hợp các vấn đề chính như sau:

### **1. Về Cấu Trúc Hệ Thống**

- **Sai lệch Best Practices**: Dù bạn hướng tới việc áp dụng MVC, modular architecture và dependency injection theo NestJS, `@auth` đang đi lệch hướng. Nó trở nên quá lớn, xử lý cả những logic không thuộc trách nhiệm của nó (ví dụ: liên quan đến profile, role).
- **Module Thiếu Tính Phân Tách**: `@auth` được thiết kế độc lập, không tận dụng `@shared` cho các thành phần tái sử dụng
- **Controller Quá Tải**: `@auth.controller.ts` chứa quá nhiều logic xử lý, vi phạm nguyên tắc separation of concerns.
- **Code Lặp và Không Clean**: Có nhiều đoạn code trùng lặp, thiếu tính tường minh, dẫn đến khó bảo trì hoặc mở rộng.
- **Dung Lượng File Quá Lớn**: Các tầng như repository, model, DTO không được phân chia rõ ràng, khiến một số file trở nên dài dòng và khó quản lý.

### **2. Về Tính Nhất Quán**

- **i18n Chưa Đồng Bộ**: Dù đã có `@i18n` và `@auth.error.ts`, nhiều message vẫn trả về dạng key-value thay vì được dịch qua `nestjs-i18n` dựa trên header `Accept-Language` hoặc query param.
- **Xử Lý Lỗi và Response Không Thống Nhất**: Một số lỗi được hardcode trong hàm, một số khác được khai báo riêng, gây混乱 (hỗn loạn).

### **3. Về Bảo Mật và Tính Linh Hoạt**

- **Cookie-based Chưa Chuẩn Hóa**: Bạn muốn mọi token (AT, RT, SLT) được trả về qua cookie thay vì response body, nhưng hiện tại điều này chưa được triển khai đồng nhất.
- **Config Thiếu Tính Linh Hoạt**:

### **4. Về API Design**

- **Endpoint Redundancy**: Có quá nhiều endpoint phục vụ mục đích tương tự (ví dụ: gửi email), làm phức tạp hóa API.

---

## **Kế Hoạch Refactor Module @auth**

Dưới đây là kế hoạch chi tiết để refactor `@auth`, được trình bày dưới dạng các bước cụ thể, nhằm giải quyết triệt để các vấn đề trên, đồng thời triển khai các tính năng bạn yêu cầu một cách tối ưu, bảo mật và theo best practices của NestJS.

### **1. Tái Cấu Trúc Kiến Trúc Module**

- **Mục Tiêu**: Phân tách rõ ràng trách nhiệm giữa các module.
- **Hành Động**:
  - Chuyển logic quản lý người dùng sang module `@profile`.
  - Giới hạn `@auth` chỉ xử lý các flow liên quan đến authentication (login, register, reset password, 2FA, sessions, devices, trust, untrust, revoke, v.v).
  - Sử dụng `@shared` cho các thành phần tái sử dụng như email service, token utilities, types/interfaces.

### **2. Chuẩn Hóa Tổ Chức Code**

- **Mục Tiêu**: Tuân thủ separation of concerns và clean code.
- **Hành Động**:
  - **Controllers**: Chỉ nhận request và trả response, chuyển logic sang services.
  - **Services**: Xử lý business logic (ví dụ: xác thực, gửi OTP, tạo token).
  - **Repositories**: Quản lý truy vấn database qua Prisma.
  - **DTOs/Interfaces**: Chuẩn hóa dữ liệu đầu vào/đầu ra.
  - Loại bỏ code lặp bằng cách đưa các hàm chung vào `@shared`.

### **3. Tăng Cường Bảo Mật**

- **Mục Tiêu**: Đảm bảo cookie-based authentication và bảo vệ flow đa bước.
- **Hành Động**:
  - Thiết lập cookie với thuộc tính `HttpOnly` và `Secure` để lưu AT (Access Token), RT (Refresh Token), SLT (Short-Lived Token).
  - Sử dụng SLT Token (JWT ngắn hạn) cho các flow đa bước để đảm bảo tính toàn vẹn phiên.
  - Mã hóa dữ liệu nhạy cảm (ví dụ: 2FA secret) trong database.

### **4. Chuẩn Hóa Xử Lý Lỗi và Message**

- **Mục Tiêu**: Đảm bảo response nhất quán và hỗ trợ đa ngôn ngữ.
- **Hành Động**:
  - Sử dụng NestJS exception filters để xử lý lỗi tập trung.
  - Áp dụng `nestjs-i18n` cho tất cả message, dựa trên `Accept-Language`.
  - Định nghĩa format response chuẩn

### **6. Tối Ưu API Endpoints**

- **Mục Tiêu**: Giảm số lượng endpoint dư thừa.
- **Hành Động**:
  - Gộp các endpoint tương tự (ví dụ: dùng `/auth/send-otp` cho nhiều flow, phân biệt qua context trong SLT Token).
  - Thiết kế API để client chỉ cần gọi và hiển thị, server xử lý toàn bộ logic.

### **7. Triển Khai Các Flow Authentication**

Dưới đây là chi tiết các flow bạn yêu cầu, được tối ưu hóa để bảo mật, tuân thủ cookie-based và giảm tải cho client-side.

#### **a. Flow Register**

- **Quy Trình**:
  1. User nhập email → Server gửi OTP, tạo SLT Token (chứa email context), lưu vào cookie.
  2. User nhập OTP → Server kiểm tra SLT Token và OTP → Nếu hợp lệ, chuyển sang bước nhập thông tin.
  3. User nhập `password`, `confirmPassword`, `firstName`, `lastName`, `username` (optional), `phoneNumber`.
     - Nếu không nhập `username`, sinh username ngẫu nhiên (kiểm tra unique).
     - `phoneNumber` phải unique.
  4. Đăng ký thành công → Xóa SLT Token → Gửi email chào mừng.
- **API**:
  - `POST /auth/send-otp`: Gửi OTP, trả về message "OTP sent".
  - `POST /auth/verify-otp`: Xác thực OTP, trả về message "OTP verified" và chuyển bước.
  - `POST /auth/register`: Hoàn tất đăng ký, trả về user info.
- **Bảo Mật**: SLT Token đảm bảo flow trong cùng phiên.

#### **b. Flow Login**

- **Quy Trình**:
  1. User nhập `email`/`username` và `password`.
  2. Server kiểm tra:
     - Nếu 2FA bật + thiết bị không trusted → Yêu cầu TOTP/Recovery Code.
     - Nếu 2FA tắt + thiết bị không trusted → Gửi OTP qua email.
  3. Xác thực thành công → Trả AT và RT qua cookie, kèm data: `username`, `roleName`, `email`, `isDeviceTrustedInSession`, `userId` (UUID), `avatar`.
- **API**:
  - `POST /auth/login`: Đăng nhập, xử lý logic theo 2FA và device trust.
  - `POST /auth/verify-otp` hoặc `POST /auth/verify-totp`: Xác thực bước 2.
- **Bảo Mật**: Thiết bị trusted bypass xác thực, AT/RT lưu trong cookie.

#### **c. Flow Reset Password**

- **Chưa Đăng Nhập**:
  1. User nhập `email`/`username` → Server gửi OTP (nếu 2FA tắt) hoặc yêu cầu TOTP/Recovery Code (nếu 2FA bật), tạo SLT Token.
  2. Xác thực thành công → Cho phép nhập `password`, `confirmPassword`.
  3. Hoàn tất → Gửi email thông báo.
- **Đã Đăng Nhập**:
  1. User nhập `currentPassword`, `password`, `confirmPassword`.
  2. Server yêu cầu OTP (2FA tắt) hoặc TOTP/Recovery Code (2FA bật).
  3. Xác thực thành công → Cập nhật password → Gửi email thông báo.
- **API**:
  - `POST /auth/reset-password/request`: Bắt đầu flow.
  - `POST /auth/verify-otp` hoặc `POST /auth/verify-totp`: Xác thực.
  - `POST /auth/reset-password/confirm`: Hoàn tất.
- **Bảo Mật**: SLT Token và email thông báo cho hành động nhạy cảm.

#### **d. Flow Login with Google**

- **Quy Trình**:
  1. User đăng nhập qua Google.
  2. Nếu 2FA bật → Yêu cầu TOTP/Recovery Code sau khi Google xác thực.
  3. Thành công → Trả AT/RT qua cookie.
- **API**:
  - `GET /auth/google`: Khởi tạo Google login.
  - `POST /auth/google/callback`: Xử lý callback, yêu cầu TOTP nếu cần.
- **Bảo Mật**: Không cho phép bypass 2FA.

#### **e. Flow Register with Google**

- **Quy Trình**:
  1. User chọn "Register with Google".
  2. Server kiểm tra:
     - Nếu email đã tồn tại → Yêu cầu liên kết (OTP hoặc password để xác minh).
     - Nếu email chưa tồn tại → Tạo tài khoản mới với `googleId`.
  3. Thành công → Trả AT/RT qua cookie.
- **API**:
  - `GET /auth/google/register`: Khởi tạo đăng ký.
  - `POST /auth/google/link`: Liên kết hoặc tạo mới.
- **Bảo Mật**: Xác minh trước khi liên kết để tránh tự động merge.

#### **f. Flow Sessions và Devices**

- **Quy Trình**:
  1. Hiển thị sessions nhóm theo `deviceId` (lưu qua cookie riêng).
  2. User có thể:
     - Revoke all sessions (bao gồm hiện tại).
     - Revoke specific sessions (trừ hiện tại).
     - Revoke device (yêu cầu OTP/TOTP).
- **API**:
  - `GET /profile/sessions`: Lấy danh sách sessions/devices.
  - `POST /profile/sessions/revoke`: Revoke sessions/devices.
- **Bảo Mật**: Xác thực cho hành động revoke.

#### **g. Flow Trust và Untrust Device**

- **Quy Trình**:
  1. Login từ device không trusted → Yêu cầu OTP/TOTP → `isDeviceTrustedInSession = false`.
  2. User trust device → Xác thực OTP/TOTP → Cập nhật `isTrusted = true`.
  3. User untrust device → Xác thực OTP/TOTP → Cập nhật `isTrusted = false`.
- **API**:
  - `POST /profile/devices/trust`: Trust device hiện tại.
  - `POST /profile/devices/untrust`: Untrust device.
- **Bảo Mật**: Xác thực cho mọi thay đổi.

#### **h. Flow 2FA**

- **Setup**:
  1. User bật 2FA → Server tạo QR code và secret.
  2. User nhập TOTP → Xác thực → Bật 2FA.
- **Disable**:
  1. User tắt 2FA → Yêu cầu TOTP/Recovery Code → Tắt 2FA → Gửi email.
- **API**:
  - `POST /auth/2fa/enable`: Tạo QR và bật 2FA.
  - `POST /auth/2fa/disable`: Tắt 2FA.
- **Bảo Mật**: Recovery Code dùng 1 lần, thông báo hành động nhạy cảm.

### **8. Điều Chỉnh Schema Prisma**

- **Users**: `userId` (UUID), `googleId`, `twoFactorSecret` (encrypted), `isTwoFactorEnabled`.
- **Sessions**: `sessionId`, `userId`, `deviceId`, `createdAt`, `expiresAt`.
- **Devices**: `deviceId`, `userId`, `isTrusted`.
- **RecoveryCodes**: `userId`, `code` (hashed), `isUsed`.

---

## **Chiến Lược Thực Thi**

1. **Phân Tích Code Hiện Tại**: Xác định logic cần di chuyển, code lặp.
2. **Tái Cấu Trúc Module**: Tách `@profile`, chuẩn hóa `@auth`.
3. **Triển Khai Từng Flow**: Bắt đầu từ Register, test kỹ trước khi sang flow khác.
4. **Database Migration**: Cập nhật schema qua Prisma.
5. **Testing**: Unit test, integration test, staging environment.
6. **Tài Liệu**: Cập nhật API docs và hướng dẫn client.

---

## **Kết Luận**

Kế hoạch này đảm bảo `@auth` được refactor để bảo mật, tối ưu, dễ bảo trì và tích hợp. File `.md` chi tiết sẽ được soạn để theo dõi tiến độ. Nếu cần thêm giải thích, hãy cho tôi biết!
