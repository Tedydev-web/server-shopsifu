import { createZodDto } from 'nestjs-zod'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { z } from 'zod'
import { UserAuthResponseSchema } from 'src/routes/auth/auth.model'

// Send OTP DTOs
export const SendOtpSchema = z.object({
  email: z.string().email(),
  purpose: z.nativeEnum(TypeOfVerificationCode),
  deviceId: z.number().optional(),
  metadata: z.record(z.any()).optional()
})

export const SendOtpResponseSchema = z.object({
  message: z.string()
})

// Verify OTP DTOs
/**
 * Schema cho việc xác minh OTP
 */
export const VerifyOtpSchema = z.object({
  code: z.string().min(1, 'Code is required'),
  purpose: z.string().optional()
})

export const VerifyOtpResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  statusCode: z.number().optional(),
  requiresDeviceVerification: z.boolean().optional(),
  requiresAdditionalVerification: z.boolean().optional(),
  redirectUrl: z.string().optional(),
  user: UserAuthResponseSchema.optional()
})

export const VerifyOtpWithRedirectSchema = z.object({
  message: z.string(),
  redirectUrl: z.string().optional()
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
