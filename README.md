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
