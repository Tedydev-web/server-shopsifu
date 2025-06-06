import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { CompleteRegistrationSchema } from 'src/routes/auth/shared/schemas'

// ===================================================================================
// Lược đồ cho nội dung yêu cầu
// ===================================================================================

// --- Registration ---
export const InitiateRegistrationSchema = z.object({
  email: z.string().email()
})

// --- Login ---
export const LoginSchema = z.object({
  emailOrUsername: z.string().min(1, 'Email or username is required'),
  password: z.string().min(1, 'Password is required'),
  rememberMe: z.boolean().optional().default(false)
})

// --- Refresh Token ---
export const RefreshTokenSchema = z.object({
  refreshToken: z.string().optional()
})

// --- Logout ---
export const LogoutSchema = z.object({
  refreshToken: z.string().optional()
})

// ===================================================================================
// Lược đồ cho dữ liệu phản hồi (sẽ được bao bọc bởi TransformInterceptor)
// ===================================================================================

// --- Login ---
// Lược đồ cho phần dữ liệu của phản hồi khi cần xác minh thêm.
export const LoginVerificationNeededResponseSchema = z.object({
  sltToken: z.string().optional(),
  verificationType: z.enum(['OTP', '2FA']).optional()
})

// --- Refresh Token ---
// Lược đồ cho phần dữ liệu của phản hồi khi mã thông báo được làm mới.
export const RefreshTokenResponseSchema = z.object({
  accessToken: z.string()
})

// ===================================================================================
// DTO Classes
// ===================================================================================

// --- Request DTOs ---
export class InitiateRegistrationDto extends createZodDto(InitiateRegistrationSchema) {}
export class CompleteRegistrationDto extends createZodDto(CompleteRegistrationSchema) {}
export class LoginDto extends createZodDto(LoginSchema) {}
export class RefreshTokenDto extends createZodDto(RefreshTokenSchema) {}
export class LogoutDto extends createZodDto(LogoutSchema) {}

// --- Response DTOs ---
// Lưu ý: Các DTO này hiện đại diện cho trường "dữ liệu" trong phản hồi API cuối cùng.
export class LoginVerificationNeededResponseDto extends createZodDto(LoginVerificationNeededResponseSchema) {}
export class RefreshTokenResponseDto extends createZodDto(RefreshTokenResponseSchema) {}
