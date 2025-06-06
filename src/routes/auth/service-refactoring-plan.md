# Kế hoạch tái cấu trúc Auth Module

## Mục tiêu tái cấu trúc

Tài liệu này mô tả kế hoạch để tái cấu trúc các phương thức trong module xác thực, nhằm tách biệt rõ ràng các trách nhiệm theo từng service. Việc tái cấu trúc này sẽ giúp cải thiện khả năng bảo trì, kiểm thử và mở rộng của hệ thống.

## Bảng phân công trách nhiệm

### TokenService

Trách nhiệm chính: Quản lý vòng đời của JWT tokens (tạo, xác thực, vô hiệu hóa)

**Giữ lại:**

- `generateAccessToken`: Tạo access token
- `generateRefreshToken`: Tạo refresh token
- `validateAccessToken`: Xác thực access token
- `validateRefreshToken`: Xác thực refresh token
- `signAccessToken`: Ký access token
- `signRefreshToken`: Ký refresh token
- `signShortLivedToken`: Ký token ngắn hạn
- `verifyAccessToken`: Xác minh access token
- `verifyRefreshToken`: Xác minh refresh token
- `signPendingLinkToken`: Ký token liên kết đang chờ xử lý
- `verifyPendingLinkToken`: Xác minh token liên kết đang chờ xử lý
- `extractTokenFromRequest`: Trích xuất token từ request
- `extractRefreshTokenFromRequest`: Trích xuất refresh token từ request
- `invalidateAccessTokenJti`: Vô hiệu hóa access token JTI
- `invalidateRefreshTokenJti`: Vô hiệu hóa refresh token JTI
- `isAccessTokenJtiBlacklisted`: Kiểm tra access token JTI có trong blacklist
- `isRefreshTokenJtiBlacklisted`: Kiểm tra refresh token JTI có trong blacklist
- `markRefreshTokenJtiAsUsed`: Đánh dấu refresh token JTI đã sử dụng
- `findSessionIdByRefreshTokenJti`: Tìm session ID từ refresh token JTI

**Cần chuyển sang SessionService:**

- `invalidateSession`: Vô hiệu hóa một session
- `archiveRevokedSession`: Lưu trữ session đã thu hồi
- `isSessionInvalidated`: Kiểm tra session đã bị vô hiệu hóa
- `invalidateAllUserSessions`: Vô hiệu hóa tất cả session của một người dùng

**Cần chuyển sang DeviceService:**

- `markDeviceForReverification`: Đánh dấu thiết bị cần xác minh lại
- `checkDeviceNeedsReverification`: Kiểm tra thiết bị cần xác minh lại
- `clearDeviceReverification`: Xóa cờ xác minh lại của thiết bị

### SessionService

Trách nhiệm chính: Quản lý phiên đăng nhập

**Cần tiếp nhận từ TokenService:**

- `invalidateSession`: Vô hiệu hóa một session
- `archiveRevokedSession`: Lưu trữ session đã thu hồi
- `isSessionInvalidated`: Kiểm tra session đã bị vô hiệu hóa
- `invalidateAllUserSessions`: Vô hiệu hóa tất cả session của một người dùng

**Chức năng hiện có:**

- `getSessions`: Lấy danh sách phiên
- `createSession`: Tạo phiên mới
- `revokeItems`: Thu hồi các phiên hoặc thiết bị

### DeviceService

Trách nhiệm chính: Quản lý thiết bị

**Cần tiếp nhận từ TokenService:**

- `markDeviceForReverification`: Đánh dấu thiết bị cần xác minh lại
- `checkDeviceNeedsReverification`: Kiểm tra thiết bị cần xác minh lại
- `clearDeviceReverification`: Xóa cờ xác minh lại của thiết bị

**Chức năng hiện có:**

- `findById`: Tìm thiết bị theo ID
- `upsertDevice`: Thêm mới hoặc cập nhật thiết bị
- `updateDeviceTrustStatus`: Cập nhật trạng thái tin cậy của thiết bị
- `updateDeviceName`: Cập nhật tên thiết bị
- `isDeviceTrustValid`: Kiểm tra tính hợp lệ của trạng thái tin cậy

### SLTService

Trách nhiệm chính: Quản lý Short-Lived Tokens (SLT) cho xác thực tạm thời

**Chức năng hiện có:**

- `createAndStoreSltToken`: Tạo và lưu SLT token
- `validateSltFromCookieAndGetContext`: Xác thực SLT cookie và lấy context
- `updateSltContext`: Cập nhật SLT context
- `finalizeSlt`: Hoàn tất SLT
- `incrementSltAttempts`: Tăng số lần thử cho SLT
- `initiateOtpWithSltCookie`: Khởi tạo OTP và lưu vào SLT Cookie

### AuthVerificationService

Trách nhiệm chính: Điều phối các luồng xác thực khác nhau

**Chức năng hiện có:**

- `initiateVerification`: Khởi tạo quá trình xác thực phù hợp
- `verifyCode`: Xác minh mã OTP hoặc 2FA
- `shouldUse2FAForPurpose`: Kiểm tra mục đích xác thực có nên dùng 2FA
- `initiateOTPVerification`: Khởi tạo xác thực OTP
- `initiate2FAVerification`: Khởi tạo xác thực 2FA
- `verifyWithOTP`: Xác thực bằng OTP
- `verifyWith2FA`: Xác thực bằng 2FA
- `handlePostVerificationActions`: Xử lý sau xác thực
- `handleLoginVerification`: Xử lý xác thực đăng nhập
- `handleRevokeSessionsVerification`: Xử lý xác thực thu hồi phiên
- `handleRevokeAllSessionsVerification`: Xử lý xác thực thu hồi tất cả phiên
- `handleUnlinkGoogleAccountVerification`: Xử lý xác thực hủy liên kết Google
- `handleDisable2FAVerification`: Xử lý xác thực tắt 2FA
- `handleRegisterVerification`: Xử lý xác thực đăng ký

## Kế hoạch triển khai

1. Tạo interface rõ ràng cho từng service
2. Triển khai các phương thức mới trong service đích
3. Loại bỏ logic hiện có và thay thế bằng ủy thác cho service mới
4. Cập nhật các module phụ thuộc để sử dụng service đích
5. Kiểm thử kỹ lưỡng sau mỗi bước chuyển đổi
 