Dựa trên yêu cầu của bạn, tôi sẽ đề xuất một phương án **best practices** để đơn giản hóa luồng xác thực trong `AuthService`, giữ nguyên các tính năng hiện có (đăng ký, đăng nhập, làm mới token, đăng xuất, đặt lại mật khẩu, OTP, 2FA) nhưng tối ưu hóa về mặt cấu trúc, bảo mật, và khả năng bảo trì. Sau đó, tôi sẽ cung cấp file `AuthService` hoàn chỉnh với mã nguồn được cải tiến, tuân thủ clean code và các tiêu chuẩn hiện đại trong phát triển web full-stack (NestJS, Prisma, Next.js).

---

## Phân tích vấn đề hiện tại

Luồng xác thực trong `AuthService` hiện tại rất chi tiết và bảo mật, nhưng có một số vấn đề khiến nó phức tạp:

1. **Độ phức tạp của phương thức**: Các phương thức như `login`, `refreshToken`, và `verifyTwoFactor` chứa nhiều logic (kiểm tra token, thiết bị, 2FA, audit log), dẫn đến khó đọc và bảo trì.
2. **Lặp lại mã**: Logic kiểm tra token, thiết bị, và audit log xuất hiện nhiều lần, chưa được tái sử dụng hiệu quả.
3. **Kết hợp chặt chẽ (tight coupling)**: Một số phương thức phụ thuộc quá nhiều vào chi tiết triển khai của `AuthRepository` hoặc `PrismaService`, làm giảm tính linh hoạt.
4. **Thiếu tính trừu tượng**: Các thao tác như xác minh OTP, tạo token, hoặc quản lý thiết bị chưa được trừu tượng hóa thành các lớp hoặc hàm riêng biệt.
5. **Quản lý cấu hình**: Các giá trị như thời gian hết hạn token (`envConfig.OTP_TOKEN_EXPIRES_IN`) được hardcode, gây khó khăn khi thay đổi.
6. **Khả năng mở rộng**: Thêm phương thức 2FA mới (như SMS) hoặc tích hợp OAuth sẽ yêu cầu sửa đổi nhiều phương thức.

---

## Phương án Best Practices

Để giải quyết các vấn đề trên và đảm bảo luồng hoạt động của bạn, tôi đề xuất các cải tiến sau, dựa trên best practices trong phát triển web với NestJS:

### 1. Tách logic thành các lớp chuyên biệt (Domain-Driven Design)

- **Mục tiêu**: Tăng tính mô-đun, giảm độ phức tạp của `AuthService`.
- **Cách làm**:
  - Tạo các lớp dịch vụ nhỏ hơn:
    - `OtpService`: Xử lý gửi, xác minh OTP.
    - `TokenService`: Quản lý access token, refresh token.
    - `DeviceService`: Quản lý thiết bị (tạo, xác minh).
    - `TwoFactorService`: Xử lý 2FA (TOTP, mã khôi phục).
    - `AuditLogService`: Ghi log (đã có sẵn).
  - `AuthService` chỉ điều phối (orchestrate) các dịch vụ này, không chứa logic phức tạp.
- **Lợi ích**:
  - Mỗi lớp có trách nhiệm duy nhất (Single Responsibility Principle).
  - Dễ kiểm thử và mở rộng (ví dụ: thêm 2FA qua SMS).

### 2. Sử dụng Command Pattern

- **Mục tiêu**: Đóng gói logic của mỗi endpoint thành các lệnh (command) riêng biệt.
- **Cách làm**:

  - Tạo các lớp command như `RegisterCommand`, `LoginCommand`, `VerifyTwoFactorCommand`.
  - Mỗi command chứa dữ liệu đầu vào và logic xử lý, được gọi bởi `AuthService`.
  - Ví dụ:

    ```typescript
    class RegisterCommand {
      constructor(
        public readonly data: RegisterBodyType & { userAgent: string; ip: string },
        private readonly services: {
          authRepo: AuthRepository
          hashing: passwordService
          roles: RolesService
        }
      ) {}

      async execute(tx: Prisma.TransactionClient) {
        // Logic đăng ký
      }
    }
    ```

- **Lợi ích**:
  - Tách biệt logic nghiệp vụ, dễ debug và kiểm thử.
  - Giảm số dòng code trong `AuthService`.

### 3. Trừu tượng hóa repository

- **Mục tiêu**: Giảm phụ thuộc vào Prisma, tăng tính linh hoạt.
- **Cách làm**:
  - Định nghĩa interface cho `AuthRepository`:
    ```typescript
    interface AuthRepository {
      findVerificationCode(input: { email: string; code: string; type: string }): Promise<VerificationCode | null>
      createUser(input: UserCreateInput): Promise<User>
      // ...
    }
    ```
  - Triển khai `PrismaAuthRepository` sử dụng Prisma.
- **Lợi ích**:
  - Dễ thay đổi ORM (ví dụ: từ Prisma sang TypeORM) mà không sửa `AuthService`.
  - Tăng khả năng kiểm thử với mock repository.

### 4. Tối ưu Audit Logging

- **Mục tiêu**: Đơn giản hóa việc ghi log mà vẫn chi tiết.
- **Cách làm**:
  - Sử dụng decorator hoặc middleware để tự động ghi audit log:
    ```typescript
    @Injectable()
    class AuditLogDecorator {
      constructor(private readonly auditLogService: AuditLogService) {}
      logAction(action: string, data: Partial<AuditLogData>) {
        // Ghi log
      }
    }
    ```
  - Áp dụng decorator cho các phương thức:
    ```typescript
    @AuditLog('USER_LOGIN_ATTEMPT')
    async login(data: LoginBodyType) {
      // Logic
    }
    ```
- **Lợi ích**:
  - Loại bỏ mã audit log lặp lại trong mỗi phương thức.
  - Đảm bảo ghi log nhất quán.

### 5. Tăng cường Type Safety

- **Mục tiêu**: Tránh lỗi runtime do type assertions.
- **Cách làm**:
  - Sử dụng Zod để validate input:
    ```typescript
    import { z } from 'zod'
    const RegisterSchema = z.object({
      email: z.string().email(),
      password: z.string().min(8),
      otpToken: z.string()
    })
    ```
  - Dùng type guards thay vì `as`:
    ```typescript
    function isVerificationToken(token: any): token is VerificationToken {
      return token && typeof token.email === 'string' && typeof token.token === 'string'
    }
    ```
- **Lợi ích**:
  - Đảm bảo dữ liệu đầu vào hợp lệ trước khi xử lý.
  - Giảm lỗi runtime.

### 6. Quản lý cấu hình tập trung

- **Mục tiêu**: Loại bỏ hardcode, dễ thay đổi cấu hình.
- **Cách làm**:
  - Tạo `ConfigService`:
    ```typescript
    @Injectable()
    class ConfigService {
      get otpExpiry(): number {
        return ms(process.env.OTP_TOKEN_EXPIRES_IN || '15m')
      }
      get refreshTokenExpiry(): number {
        return ms(process.env.REFRESH_TOKEN_COOKIE_MAX_AGE || '7d')
      }
    }
    ```
- **Lợi ích**:
  - Cấu hình tập trung, dễ điều chỉnh qua biến môi trường.
  - Tăng tính bảo trì.

### 7. Rate Limiting và Password Policy

- **Mục tiêu**: Tăng bảo mật và trải nghiệm người dùng.
- **Cách làm**:
  - Thêm rate limiting cho `sendOTP`:
    ```typescript
    @RateLimit({ points: 5, duration: 60 })
    async sendOTP(data: SendOTPBodyType) {
      // Logic
    }
    ```
  - Áp dụng chính sách mật khẩu:
    ```typescript
    private validatePassword(password: string) {
      if (password.length < 8 || !/[A-Z]/.test(password)) {
        throw new HttpException('Password too weak', HttpStatus.BAD_REQUEST);
      }
    }
    ```
- **Lợi ích**:
  - Ngăn chặn lạm dụng API.
  - Đảm bảo mật khẩu mạnh.

### 8. Tài liệu hóa và kiểm thử

- **Mục tiêu**: Tăng khả năng bảo trì và độ tin cậy.
- **Cách làm**:
  - Thêm JSDoc cho mỗi phương thức.
  - Viết unit test với Jest:
    ```typescript
    describe('AuthService', () => {
      it('should register user successfully', async () => {
        const result = await authService.register({ email: 'test@example.com', ... });
        expect(result.email).toBe('test@example.com');
      });
    });
    ```
- **Lợi ích**:
  - Dễ hiểu mã hơn.
  - Đảm bảo chất lượng qua kiểm thử.

### 9. Hỗ trợ mở rộng

- **Mục tiêu**: Dễ dàng thêm tính năng mới (như 2FA qua SMS hoặc OAuth).
- **Cách làm**:
  - Sử dụng Strategy Pattern cho 2FA:
    ```typescript
    interface TwoFactorStrategy {
      verify(data: { email: string; code: string; secret?: string }): Promise<boolean>
    }
    class TOTPStrategy implements TwoFactorStrategy {
      async verify(data) {
        // Logic TOTP
      }
    }
    ```
  - Định nghĩa interface cho các luồng xác thực khác (OAuth, SSO).
- **Lợi ích**:
  - Dễ tích hợp phương thức 2FA mới hoặc nhà cung cấp xác thực bên thứ ba.

---

## Luồng hoạt động mong muốn (giữ nguyên)

Luồng xác thực hiện tại của bạn bao gồm:

1. **Đăng ký**: Gửi OTP → Xác minh OTP → Tạo tài khoản.
2. **Đăng nhập**: Kiểm tra email/mật khẩu → Nếu có 2FA, yêu cầu TOTP/mã khôi phục → Trả về token.
3. **Làm mới token**: Kiểm tra refresh token và thiết bị → Tạo token mới.
4. **Đăng xuất**: Xóa refresh token và cookie.
5. **Đặt lại mật khẩu**: Gửi OTP → Xác minh OTP → Cập nhật mật khẩu.
6. **Quản lý 2FA**: Bật (TOTP + mã khôi phục), tắt, xác minh.

Phương án trên giữ nguyên luồng này nhưng đơn giản hóa triển khai, tăng tính tái sử dụng và bảo trì.

---

---

## Giải thích về file `AuthService`

1. **Cấu trúc**:

   - Tách logic phức tạp vào các dịch vụ phụ trợ (`OtpService`, `DeviceService`, `TokenService`, `TwoFactorService`).
   - Mỗi phương thức trong `AuthService` chỉ điều phối, không chứa logic chi tiết.

2. **Type Safety**:

   - Sử dụng Zod để validate input (`RegisterSchema`).
   - Loại bỏ type assertions, sử dụng type guards và optional chaining.

3. **Audit Logging**:

   - Đơn giản hóa audit log bằng cách sử dụng object `auditLog` và ghi log trong `try-catch`.

4. **Cấu hình**:

   - Sử dụng `ConfigService` để quản lý thời gian hết hạn token, cookie, v.v.

5. **Bảo mật**:

   - Kiểm tra thiết bị, token, và 2FA được thực hiện bởi các dịch vụ chuyên biệt.
   - Áp dụng validation mật khẩu (ít nhất 8 ký tự) trong `RegisterSchema`.

6. **Logging**:

   - Sử dụng `Logger` của NestJS để ghi log debug.

7. **Khả năng mở rộng**:
   - Các dịch vụ phụ trợ được thiết kế để dễ dàng thêm phương thức 2FA mới hoặc tích hợp OAuth.

---

## Các dịch vụ phụ trợ (giả định)

Để `AuthService` hoạt động, bạn cần triển khai các dịch vụ sau:

1. **`OtpService`**:

   - `sendOTP`: Gửi OTP qua email.
   - `verifyOTP`: Xác minh OTP và tạo token OTP.
   - `validateOTPToken`: Kiểm tra token OTP.
   - `create2FASession`: Tạo phiên 2FA.
   - `deleteOTPToken`: Xóa token OTP.

2. **`DeviceService`**:

   - `ensureDevice`: Tạo hoặc lấy ID thiết bị.
   - `validateDevice`: Kiểm tra thiết bị khớp với user agent và IP.

3. **`TokenService`**:

   - `hashPassword`: Mã hóa mật khẩu.
   - `comparePassword`: So sánh mật khẩu.
   - `generateTokens`: Tạo access token và refresh token.
   - `validateRefreshToken`: Kiểm tra refresh token.
   - `markRefreshTokenUsed`: Đánh dấu refresh token đã sử dụng.
   - `deleteRefreshToken`: Xóa refresh token.
   - `deleteAllRefreshTokens`: Xóa tất cả refresh token của người dùng.
   - `setTokenCookies`: Đặt cookie cho token.
   - `clearTokenCookies`: Xóa cookie.

4. **`TwoFactorService`**:
   - `setupTOTP`: Tạo secret và URI cho TOTP.
   - `confirmTOTPSetup`: Xác nhận thiết lập TOTP, tạo mã khôi phục.
   - `verifyTOTP`: Xác minh mã TOTP.
   - `verifyRecoveryCode`: Xác minh mã khôi phục.
   - `deleteRecoveryCodes`: Xóa mã khôi phục.

Nếu bạn cần tôi cung cấp mã nguồn chi tiết cho các dịch vụ này, hãy cho tôi biết!

---

## Kết luận

Phương án trên đơn giản hóa luồng xác thực của bạn bằng cách tách logic thành các dịch vụ chuyên biệt, sử dụng command pattern, và áp dụng best practices như type safety, audit logging tự động, và cấu hình tập trung. File `AuthService` được cung cấp đảm bảo giữ nguyên các tính năng hiện có, đồng thời sạch hơn, dễ bảo trì hơn, và sẵn sàng mở rộng.

Nếu bạn muốn tôi triển khai thêm các dịch vụ phụ trợ, viết unit test, hoặc tích hợp với frontend Next.js, hãy báo cho tôi!
