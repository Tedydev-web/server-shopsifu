import { createZodDto } from 'nestjs-zod'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { z } from 'zod'
import { UserAuthResponseSchema } from 'src/routes/auth/auth.model'

// Send OTP DTOs
export const SendOtpSchema = z.object({
  email: z.string().email('Invalid email format'),
  type: z.nativeEnum(TypeOfVerificationCode, {
    errorMap: () => ({ message: 'Loại mã xác thực không hợp lệ' })
  })
})

export const SendOtpResponseSchema = z.object({
  message: z.string()
})

// Verify OTP DTOs
export const VerifyOtpSchema = z.object({
  code: z.string().min(6).max(6),
  rememberMe: z.boolean().optional().default(false)
})

export const VerifyOtpResponseSchema = z.object({
  message: z.string(),
  statusCode: z.number().optional(),
  data: UserAuthResponseSchema.optional()
})

export const VerifyOtpWithRedirectSchema = z.object({
  message: z.string(),
  redirectUrl: z.string().optional()
})

// UserProfile Schema dùng cho response
export const UserProfileResponseSchema = z.object({
  username: z.string().nullable(),
  avatar: z.string().nullable()
})

// Schema khi xác minh OTP thành công và hoàn tất đăng nhập
// Sử dụng UserAuthResponseSchema để đảm bảo đồng bộ với login response
export const VerifyOtpSuccessResponseSchema = z.object({
  message: z.string(),
  user: UserAuthResponseSchema
})

// DTO classes
export class SendOtpDto extends createZodDto(SendOtpSchema) {}
export class SendOtpResponseDto extends createZodDto(SendOtpResponseSchema) {}
export class VerifyOtpDto extends createZodDto(VerifyOtpSchema) {}
export class VerifyOtpResponseDto extends createZodDto(VerifyOtpResponseSchema) {}
export class VerifyOtpWithRedirectDto extends createZodDto(VerifyOtpWithRedirectSchema) {}
export class VerifyOtpSuccessResponseDto extends createZodDto(VerifyOtpSuccessResponseSchema) {}
