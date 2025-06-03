# Xác thực hai yếu tố (2FA)

## Flow xác thực hai yếu tố

Hệ thống hỗ trợ xác thực hai yếu tố (2FA) sử dụng chuẩn TOTP (Time-based One-Time Password) tương thích với các ứng dụng như Google Authenticator, Authy, hay Microsoft Authenticator.

### 1. Thiết lập 2FA

**Request:**

```http
POST /api/v1/auth/2fa/setup
Authorization: Bearer {access_token}
Content-Type: application/json

{}
```

**Response:**

```json
{
  "secret": "BASE32_SECRET_KEY",
  "uri": "data:image/png;base64,..."
}
```

**Hướng dẫn hiển thị trên Frontend:**

```jsx
// React component hiển thị QR code và secret key an toàn
const Setup2FA = ({ secret, uri }) => {
  const [showSecret, setShowSecret] = useState(false)

  return (
    <div className='setup-2fa-container'>
      <h3>Thiết lập xác thực hai yếu tố</h3>

      <div className='qr-container'>
        <img src={uri} alt='QR Code cho 2FA' width='200' height='200' />
      </div>

      <div className='instructions'>
        <p>1. Quét mã QR bằng ứng dụng xác thực như Google Authenticator hoặc Authy</p>
        <p>2. Hoặc nhập mã bí mật thủ công vào ứng dụng của bạn</p>
      </div>

      <div className='secret-key-container'>
        {!showSecret ? (
          <button className='show-secret-button' onClick={() => setShowSecret(true)}>
            Hiển thị mã bí mật
          </button>
        ) : (
          <>
            <div className='secret-display'>
              <code>{secret}</code>
              <button className='copy-button' onClick={() => navigator.clipboard.writeText(secret)}>
                Copy
              </button>
            </div>
            <button className='hide-secret-button' onClick={() => setShowSecret(false)}>
              Ẩn mã bí mật
            </button>
          </>
        )}
      </div>
    </div>
  )
}
```

**Lưu ý**: Secret key chỉ nên hiển thị khi người dùng chủ động yêu cầu, và nên ẩn lại sau một thời gian ngắn.

### 2. Xác nhận thiết lập 2FA

**Request:**

```http
POST /api/v1/auth/2fa/confirm-setup
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "totpCode": "123456"
}
```

**Response:**

```json
{
  "message": "Two-factor authentication has been enabled successfully.",
  "recoveryCodes": [
    "ABCD-1234-EFGH-5678",
    ...
  ]
}
```

**Hiển thị recovery codes trên frontend:**

```jsx
// Hiển thị và lưu trữ mã khôi phục
const RecoveryCodes = ({ recoveryCodes }) => {
  const [hasCopied, setHasCopied] = useState(false)
  const [hasDownloaded, setHasDownloaded] = useState(false)

  const handleCopyAll = () => {
    const allCodes = recoveryCodes.join('\n')
    navigator.clipboard.writeText(allCodes)
    setHasCopied(true)
  }

  const handleDownload = () => {
    const allCodes = recoveryCodes.join('\n')
    const blob = new Blob([allCodes], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'shopsifu-recovery-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
    setHasDownloaded(true)
  }

  return (
    <div className='recovery-codes-container'>
      <h3>Mã khôi phục của bạn</h3>
      <p className='warning'>⚠️ Lưu trữ các mã này ở nơi an toàn. Đây là lần duy nhất bạn thấy chúng.</p>

      <div className='codes-list'>
        {recoveryCodes.map((code, index) => (
          <div key={index} className='recovery-code'>
            <code>{code}</code>
          </div>
        ))}
      </div>

      <div className='actions'>
        <button onClick={handleCopyAll} className='copy-button'>
          {hasCopied ? '✓ Đã sao chép' : 'Sao chép tất cả'}
        </button>

        <button onClick={handleDownload} className='download-button'>
          {hasDownloaded ? '✓ Đã tải xuống' : 'Tải xuống (.txt)'}
        </button>
      </div>

      <div className='confirmation'>
        <label>
          <input type='checkbox' required />
          Tôi đã lưu trữ các mã khôi phục ở nơi an toàn
        </label>
        <button className='continue-button'>Tiếp tục</button>
      </div>
    </div>
  )
}
```

### 3. Xác minh 2FA khi đăng nhập

**Request:**

```http
POST /api/v1/auth/2fa/verify
Content-Type: application/json

{
  "code": "123456",
  "rememberMe": false
}
```

**Response thành công (thiết bị đã tin cậy):**

```json
{
  "message": "Two-factor authentication verified successfully.",
  "requiresDeviceVerification": false,
  "user": {
    "id": 10,
    "email": "user@example.com",
    "roleName": "USER",
    "isDeviceTrustedInSession": true,
    "userProfile": {
      "firstName": "John",
      "lastName": "Doe",
      "username": "johndoe",
      "avatar": "https://example.com/avatar.jpg"
    }
  }
}
```

**Response khi cần xác minh thêm thiết bị (thiết bị chưa tin cậy):**

```json
{
  "message": "Device verification required",
  "requiresDeviceVerification": true
}
```

Trong trường hợp này, hệ thống sẽ tự động gửi OTP qua email và frontend cần chuyển người dùng đến trang xác minh thiết bị.

**Xác minh thiết bị sau khi xác minh 2FA:**

```http
POST /api/v1/auth/otp/verify
Content-Type: application/json

{
  "code": "123456"
}
```

**Response:**

```json
{
  "message": "OTP verified successfully",
  "user": {
    "id": 10,
    "email": "user@example.com",
    "roleName": "USER",
    "isDeviceTrustedInSession": false,
    "userProfile": {
      "username": "johndoe",
      "avatar": "https://example.com/avatar.jpg"
    }
  },
  "isTwoFactorEnabled": true
}
```

### 4. Vô hiệu hóa 2FA

**Request:**

```http
POST /api/v1/auth/2fa/disable
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "code": "123456",
  "method": "TOTP" // "TOTP", "RECOVERY_CODE", hoặc "PASSWORD"
}
```

**Response:**

```json
{
  "message": "Two-factor authentication has been disabled successfully."
}
```

### 5. Tạo lại mã khôi phục

**Request:**

```http
POST /api/v1/auth/2fa/regenerate-recovery-codes
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "code": "123456"
}
```

**Response:**

```json
{
  "message": "New recovery codes have been generated successfully.",
  "recoveryCodes": [
    "JKLM-9012-NOPQ-3456",
    ...
  ]
}
```

## Các loại mã xác thực

1. **TOTP**: Mã 6 chữ số được tạo ra bởi ứng dụng authenticator
2. **Recovery Code**: Mã khôi phục dạng "ABCD-1234-EFGH-5678"
3. **Password**: Mật khẩu hiện tại của người dùng (chỉ dùng để vô hiệu hóa 2FA)

## Lưu ý về bảo mật và Best Practices

- **Secret Key**:

  - KHÔNG lưu trữ secret key trong localStorage/sessionStorage
  - KHÔNG lưu secret key trong database phía client
  - Hiển thị secret key CHỈ khi người dùng cần nhập thủ công
  - Format secret key để dễ đọc (nhóm theo từng 4 ký tự)
  - Tự động ẩn secret key sau 5 phút không tương tác

- **Recovery Codes**:

  - Khuyến khích người dùng tải xuống hoặc in ra giấy
  - Không hiển thị mã khôi phục sau khi hoàn tất thiết lập
  - Yêu cầu xác nhận người dùng đã lưu mã khôi phục

- **QR Code**:

  - Tự động làm mới QR code sau một thời gian (10 phút)
  - Thêm tính năng zoom QR code cho người dùng mobile

- **Frontend**:
  - Sử dụng background mờ (blur) khi hiển thị mã nhạy cảm
  - Tự động ẩn sau một khoảng thời gian ngắn

## Triển khai API 2FA

### Phương pháp cài đặt API

Để đảm bảo tính ổn định và nhất quán, API 2FA được triển khai bằng phương pháp trực tiếp, không sử dụng `ZodSerializerDto` để serialization response. Điều này giúp:

1. **Kiểm soát đầy đủ** việc serialization và định dạng response
2. **Giải quyết triệt để các vấn đề** với NestJS serialization pipeline
3. **Đảm bảo API hoạt động nhất quán** trên mọi môi trường

Các endpoint sử dụng mẫu triển khai sau:

```typescript
@Post('endpoint')
@UseGuards(AccessTokenGuard)
@HttpCode(HttpStatus.OK)
async endpoint(
  @ActiveUser() activeUser: AccessTokenPayload,
  // Other parameters...
  @Res({ passthrough: false }) res: Response
): Promise<void> {
  try {
    const result = await this.service.doSomething();

    // Direct response control
    res.status(200).json({
      field1: result.field1,
      field2: result.field2
    });
  } catch (error) {
    // Error handling
  }
}
```

### Lưu ý về response validation

Mặc dù không sử dụng serialization tự động, chúng tôi vẫn đảm bảo tính nhất quán của response thông qua:

1. **TypeScript interfaces** để kiểm tra kiểu dữ liệu
2. **Kiểm tra kỹ lưỡng** dữ liệu trong services
3. **Logging chi tiết** để dễ dàng debug và theo dõi

### Lưu ý khi mở rộng API

Khi thêm tính năng mới cho 2FA API:

1. Đảm bảo tuân theo mẫu response trực tiếp qua `res.status(200).json()`
2. Không sử dụng `@ZodSerializerDto` để tránh xung đột serialization
3. Bao gồm xử lý lỗi phù hợp với `HttpException`

## Quy trình xác thực hai yếu tố (2FA)

### Thiết lập 2FA

Quy trình thiết lập 2FA đã được tối ưu hóa để đơn giản và bảo mật:

1. **Bắt đầu thiết lập** - Gọi API `POST /api/v1/auth/2fa/setup`

   - Không cần gửi body data
   - Hệ thống sẽ trả về secret key và QR code

2. **Xác nhận thiết lập** - Gọi API `POST /api/v1/auth/2fa/confirm-setup`

   - Gửi mã TOTP từ ứng dụng authenticator (không cần OTP từ email)
   - Hệ thống sẽ trả về mã khôi phục (recovery codes)

3. **Lưu trữ mã khôi phục** - Người dùng cần lưu trữ mã khôi phục ở nơi an toàn

### Đăng nhập với 2FA

Sau khi 2FA đã được bật:

1. **Đăng nhập thông thường** - Nhập email/username và mật khẩu

   - Hệ thống luôn ưu tiên xác thực 2FA trước nếu tài khoản đã bật 2FA
   - Người dùng sẽ được chuyển đến trang nhập mã xác thực 2FA

2. **Xác thực 2FA** - Gọi API `POST /api/v1/auth/2fa/verify`

   - Gửi mã TOTP từ ứng dụng authenticator hoặc mã khôi phục
   - Nếu thiết bị chưa được tin cậy, hệ thống sẽ yêu cầu xác minh thêm bằng OTP qua email

3. **Xác minh thiết bị mới** (nếu cần) - Gọi API `POST /api/v1/auth/otp/verify`
   - Nhập OTP đã được gửi qua email
   - Đăng nhập hoàn tất sau khi xác minh thiết bị

### Thứ tự ưu tiên xác minh

Hệ thống tuân thủ thứ tự xác minh an toàn nhất:

1. **Xác minh 2FA** - Nếu tài khoản đã bật 2FA, luôn yêu cầu xác minh 2FA trước
2. **Xác minh thiết bị** - Sau khi xác minh 2FA thành công, kiểm tra xem thiết bị đã tin cậy hay chưa
3. **Hoàn tất đăng nhập** - Chỉ hoàn tất quá trình đăng nhập sau khi đã vượt qua tất cả các bước xác minh cần thiết

### Lưu ý quan trọng

- **Không yêu cầu OTP qua email** khi thiết lập 2FA - Quy trình đã được đơn giản hóa
- Thứ tự kiểm tra đã được tối ưu trong quá trình đăng nhập để đảm bảo tài khoản 2FA luôn được xác thực đúng cách
- Các thông tin trạng thái được bảo vệ bằng SLT token, không lưu trữ dài hạn trong cơ sở dữ liệu

# Shopsifu Server

## Xác thực Google OAuth Tối Ưu (3 Endpoint)

### Biến môi trường cần thiết

```env
# Google OAuth2 Configuration
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/api/v1/auth/social/google/callback

# Cookie Configuration (Cấu hình cookie hoạt động với OAuth)
COOKIE_SECURE=true  # Đặt false trong môi trường development nếu không dùng HTTPS
COOKIE_SAME_SITE=none
```

### Flow Xác thực Google OAuth (3 Endpoint)

#### 1. Lấy URL xác thực Google

```
GET /api/v1/auth/social/google?action=login|register|link&redirectUrl=http://example.com/callback
```

Tham số:

- `action`: loại hành động xác thực
  - `login`: Đăng nhập với tài khoản Google đã liên kết
  - `register`: Đăng ký tài khoản mới bằng Google
  - `link`: Liên kết tài khoản Google với tài khoản hiện tại
- `redirectUrl`: URL chuyển hướng sau khi xác thực hoàn tất (tùy chọn)

Phản hồi:

```json
{
  "status": "success",
  "data": {
    "url": "https://accounts.google.com/o/oauth2/auth?client_id=..."
  }
}
```

#### 2. Xử lý Callback từ Google

```
GET /api/v1/auth/social/google/callback?code=[Code]&state=[State]
```

Tham số:

- `code`: Mã xác thực từ Google
- `state`: Dữ liệu trạng thái (đã mã hóa)

Phản hồi (5 trạng thái có thể):

1. Thành công:

```json
{
  "status": "success",
  "user": {
    "id": 123,
    "email": "user@example.com",
    "roleName": "USER",
    "isDeviceTrustedInSession": false,
    "userProfile": { ... }
  }
}
```

2. Yêu cầu 2FA:

```json
{
  "status": "two_factor_required",
  "data": {
    "requiresTwoFactorAuth": true,
    "twoFactorMethod": "TOTP",
    "message": "Vui lòng xác thực 2FA"
  }
}
```

3. Yêu cầu xác minh thiết bị:

```json
{
  "status": "device_verification_required",
  "data": {
    "requiresDeviceVerification": true,
    "message": "Vui lòng xác minh thiết bị"
  }
}
```

4. Yêu cầu liên kết tài khoản:

```json
{
  "status": "linking_required",
  "data": {
    "needsLinking": true,
    "existingUserId": 123,
    "existingUserEmail": "user@example.com",
    "googleId": "google-id",
    "googleEmail": "user@gmail.com",
    "googleName": "User Name",
    "googleAvatar": "https://...",
    "message": "Tài khoản Google chưa được liên kết"
  }
}
```

5. Lỗi:

```json
{
  "status": "error",
  "error": {
    "errorCode": "ERROR_CODE",
    "errorMessage": "Thông báo lỗi",
    "redirectToError": true
  }
}
```

#### 3. Xác thực và xử lý các hoạt động

```
POST /api/v1/auth/social/verify
```

Body:

```json
{
  "action": "2fa|device|link|unlink|pending-link-details|cancel-link",
  "code": "123456", // Cho 2FA, device verification
  "password": "password123", // Cho link, unlink
  "rememberMe": true // Cho 2FA, device
}
```

Các action:

- `2fa`: Xác minh 2FA (yêu cầu code)
- `device`: Xác minh thiết bị không tin cậy (yêu cầu code)
- `link`: Hoàn tất liên kết tài khoản (yêu cầu password)
- `unlink`: Hủy liên kết Google (yêu cầu đăng nhập)
- `pending-link-details`: Lấy thông tin liên kết đang chờ
- `cancel-link`: Hủy liên kết đang chờ

Phản hồi:

```json
{
  "status": "success|error",
  "message": "Thông báo",
  "user": { ... }  // Nếu đăng nhập thành công
}
```

### Ví dụ luồng xác thực

1. Đăng nhập bằng Google:

   - Gọi `GET /api/v1/auth/social/google?action=login`
   - Chuyển hướng đến Google để xác thực
   - Google chuyển hướng đến callback
   - Nếu yêu cầu 2FA, gọi `POST /api/v1/auth/social/verify` với action="2fa" và code
   - Nếu yêu cầu xác minh thiết bị, gọi `POST /api/v1/auth/social/verify` với action="device" và code

2. Đăng ký bằng Google:

   - Gọi `GET /api/v1/auth/social/google?action=register`
   - Chuyển hướng đến Google để xác thực
   - Google chuyển hướng đến callback
   - Nếu tài khoản được tạo thành công, đăng nhập tự động

3. Liên kết tài khoản:
   - Đăng nhập vào hệ thống trước
   - Gọi `GET /api/v1/auth/social/google?action=link`
   - Chuyển hướng đến Google để xác thực
   - Google chuyển hướng đến callback
   - Nếu cần liên kết, gọi `POST /api/v1/auth/social/verify` với action="link" và password

### Ưu điểm của cách triển khai mới

1. **Giảm số lượng endpoint**: Từ 5 xuống còn 3, giúp API đơn giản hơn
2. **Thống nhất giao diện**: Cùng một mẫu phản hồi cho tất cả các endpoint
3. **Bảo mật cao**:
   - Nonce để chống CSRF
   - Cookie HttpOnly và Secure
   - Không bỏ qua xác thực 2FA
   - Thông báo qua email khi có thay đổi
4. **Dễ sử dụng**: Client chỉ cần xử lý 3 endpoint và 5 trạng thái

### Lưu ý bảo mật

- Luôn sử dụng HTTPS trong môi trường production
- Đặt `COOKIE_SECURE=true` và `COOKIE_SAME_SITE=none` trong production
- Tất cả cookie nhạy cảm đều được thiết lập với `httpOnly=true`
- Triển khai rate limiting để tránh tấn công brute-force
- Giới hạn số lần thử xác minh và khóa tài khoản tạm thời nếu vượt quá
