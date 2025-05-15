uồng đăng nhập với xác thực hai yếu tố (2FA) là một phần quan trọng trong công việc bảo vệ tài khoản người dùng, đặc biệt khi hệ thống hỗ trợ cả TOTP (Mật khẩu một lần dựa trên thời gian) và OTP qua email. Bài viết này phân tích phương pháp thực tiễn tốt nhất mà hệ thống hiện hành ứng dụng này, xem xét cách đánh giá hợp lý dự án của bạn với API và cơ sở dữ liệu hiện có, đồng thời đảm bảo không thay đổi quá nhiều cấu trúc hiện tại.

Phân tích yêu cầu
Dựa trên lược đồ Prisma và API điểm cuối của bạn, hệ thống hiện tại được hỗ trợ:

Bảng User với trường totpSecret để xác định trạng thái 2FA.
Các điểm cuối như /auth/otp , /auth/verify-code , /auth/register , /auth/reset-password , và /auth/login .
Hỗ trợ cả TOTP và OTP qua email, với người dùng có thể chọn một trong hai khi đã bật 2FA.
Vấn đề chính là ở frontend (FE), làm sao để biết người dùng đã bật 2FA chưa trước khi đăng nhập, để hiển thị giao diện phù hợp (nhập TOTP hoặc nút gửi OTP). Vì lý do bảo mật, không thể tiết lộ thông tin 2FA trước khi xác thực email/mật khẩu, nên cần một bước đăng nhập luồng.

Các phương pháp hay nhất từ ​​các hệ thống lớn
Nghiên cứu nghiên cứu từ các tài liệu như OneLogin Developers: Multi-Factor Authentication Tổng quan , FusionAuth: API đăng nhập và OWASP: Multifactor Authentication Cheat Sheet , các hệ thống lớn áp dụng luồng sau:

Đăng nhập ban đầu với email và mật khẩu :
Người dùng gửi email và mật khẩu đăng nhập API.
Nếu thông tin đúng, hệ thống kiểm tra trạng thái 2FA (thường dựa trên một trường như totpSecret trong cơ sở dữ liệu).
Nếu 2FA chưa được kích hoạt, hãy trả về quyền truy cập mã thông báo và hoàn tất.
Nếu đã bật 2FA, hãy trả về một mã thông báo tạm thời (ví dụ: loginSessionToken hoặc twoFactorId ) và thông báo yêu cầu bổ sung xác thực.
Xác thực 2FA :
Giao diện người dùng hiển thị giao diện cho người dùng lựa chọn phương thức 2FA (TOTP hoặc OTP).
Với TOTP, người dùng nhập mã từ ứng dụng như Google Authenticator.
Với OTP, hệ thống gửi email mã hóa (thông qua điểm cuối như /auth/otp ), sau đó người dùng nhập mã hóa để xác thực.
Gửi mã xác thực và mã thông báo tạm thời đến một điểm cuối dành riêng (ví dụ: /auth/2fa/verify ) để hoàn tất đăng nhập.
Người dùng bảo mật và trải nghiệm :
Đảm bảo tạm thời mã thông báo có thời hạn ngắn (ví dụ: 5 phút) để giảm thiểu rủi ro khi sử dụng.
Không tiết lộ thông tin 2FA trước khi xác thực email/mật khẩu, kèm theo nguyên tắc bảo mật của OWASP.
Cho phép người dùng lựa chọn phương thức 2FA để tăng cường hoạt động của linh hoạt, như được đề xuất trong Rublon: Thực tiễn tốt nhất về bảo mật 2FA .
Thiết kế chi tiết cho dự án của bạn
Dựa trên API và lược đồ hiện tại, các phương pháp thực hành tốt nhất có thể được tích hợp như sau:

1. Cập nhật endpoint /auth/login
   Nội dung yêu cầu:
   json

Sao chép
{
"email": "user@example.com",
"password": "password123"
}
Logic xử lý:
Kiểm tra email và mật khẩu, nếu không hợp lệ, hãy trả về lỗi 401.
Nếu hợp lệ, hãy kiểm tra totpSecret trong bảng User :
Nếu totpSecret là null (2FA chưa bật), hãy tạo accessToken và RefreshToken , trả về:
json

Sao chép
{
"accessToken": "jwt_access_token",
"refreshToken": "jwt_refresh_token"
}
Nếu totpSecret không rỗng (đã bật 2FA), hãy tạo loginSessionToken (UUID, thời hạn 5 phút), lưu vào bảng OtpToken với loại: LOGIN hoặc một bảng tạm thời và trả về:
json

Sao chép
{
"loginSessionToken": "uuid_or_jwt",
"message": "2FA required",
"2faEnabled": true
}
Lợi ích: Không cần thay đổi lược đồ, tận dụng bảng OtpToken đã có. 2. Thêm điểm cuối /auth/2fa/verify
Nội dung yêu cầu:
json

Sao chép
{
"loginSessionToken": "uuid_or_jwt",
"method": "TOTP" | "OTP",
"code": "123456"
}
Logic xử lý:
Kiểm tra loginSessionToken trong OtpToken hoặc bảng tạm thời, đảm bảo chưa hết hạn.
Nếu phương pháp là "TOTP":
Sử dụng thư viện như otplib để xác thực mã với totpSecret của người dùng.
Nếu phương thức là "OTP":
Kiểm tra mã trong bảng Mã xác minh với loại: ĐĂNG NHẬP và email tương ứng.
Nếu xác thực thành công, hãy tạo accessToken và RefreshToken , lưu RefreshToken vào bảng RefreshToken và trả về:
json

Sao chép
{
"accessToken": "jwt_access_token",
"refreshToken": "jwt_refresh_token"
}
Lợi ích: Tách logic xác thực 2FA, dễ dàng mở rộng cho các phương thức khác. 3. Sử dụng endpoint hiện có
/auth/otp : Gửi OTP với loại: "ĐĂNG NHẬP" khi người dùng chọn phương thức OTP trong giao diện 2FA.
/auth/verify-code : Có thể sử dụng để xác minh OTP trước, nhưng trong luồng hợp lý này, logic verify OTP được tích hợp vào /auth/2fa/verify để đơn giản hóa. 4. Thiết kế Frontend
Bước 1: Form đăng nhập ban đầu
Hiển thị biểu mẫu với email và mật khẩu , gửi đến /auth/login .
Xử lý phản hồi:
Nếu nhận được accessToken và RefreshToken , hãy lưu vào localStorage/cookie, chuyển hướng đến trang chính.
Nếu nhận được loginSessionToken và 2faEnabled: true , chuyển sang UI xác thực 2FA.
Bước 2: Giao diện xác thực 2FA
Hiển thị:
Nhập để nhập mã TOTP.
Nút "Gửi OTP" để yêu cầu mã OTP qua email, gọi /auth/otp với kiểu: "LOGIN" .
Người dùng mã hóa đầu vào (TOTP hoặc OTP), gửi đến /auth/2fa/verify with loginSessionToken .
Nếu thành công, hãy nhận accessToken và RefreshToken , hoàn tất đăng nhập.
Lợi ích: FE auto điều chỉnh UI dựa trên phản hồi từ /auth/login , không cần truy cập thông tin nhạy cảm trước khi đăng nhập, kèm theo nguyên tắc bảo mật.
Bảng so sánh với các hệ thống lớn

Hệ thống lớn Luồng đăng nhập 2FA Điểm tương đồng với dự án
MộtĐăng nhập Kiểm tra mật khẩu, nếu cần 2FA, trả twoFactorId , xác minh qua API riêng Tương tự với loginSessionToken và /auth/2fa/verify
FusionAuth Trạng thái thanh toán API đăng nhập 242 nếu cần 2FA, hoàn tất bổ sung API Use totpSecret để kiểm tra, phù hợp với lược đồ hiện tại
Google/Facebook Đăng nhập, nếu bật 2FA, yêu cầu TOTP hoặc OTP qua email Hỗ trợ TOTP và OTP, phương thức người dùng lựa chọn
Ưu điểm của phương án
Bảo mật: Không tiết lộ trạng thái 2FA trước khi xác thực, cộng theo OWASP.
Tính hoạt động: Người dùng chọn TOTP hoặc OTP, tăng trải nghiệm cho người dùng.
Tối ưu hóa: Không cần thay đổi lược đồ, sử dụng bảng User , VerificationCode , OtpToken .
Kết luận
Phương pháp này là các phương pháp hay nhất, phù hợp với các hệ thống lớn như OneLogin, FusionAuth và kèm theo OWASP hướng dẫn. Nó tích hợp tốt với API và hiện tại lược đồ, chỉ cần thêm điểm cuối /auth/2fa/verify và điều chỉnh logic /auth/login , đảm bảo bảo mật và trải nghiệm người dùng mượt mà.
