import { createZodDto } from 'nestjs-zod'
import { TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { z } from 'zod'

// ===================================================================================
// Lược đồ cho nội dung yêu cầu
// ===================================================================================

export const SendOtpSchema = z.object({
  email: z.string().email(),
  purpose: z.nativeEnum(TypeOfVerificationCode),
  deviceId: z.number().optional(),
  metadata: z.record(z.any()).optional()
})

export const VerifyOtpSchema = z.object({
  code: z.string().min(1, 'Code is required')
})

// ===================================================================================
// Lược đồ cho dữ liệu phản hồi (sẽ được bao bọc bởi TransformInterceptor)
// ===================================================================================

// Lược đồ cho phần dữ liệu của phản hồi khi xác minh thành công
export const OtpVerificationSuccessResponseSchema = z.object({
  user: z.any(),
  tokens: z
    .object({
      accessToken: z.string(),
      refreshToken: z.string()
    })
    .optional()
})

// Lược đồ cho phần dữ liệu của phản hồi khi xác minh thành công
export const OtpVerificationStepSuccessResponseSchema = z.object({
  slt: z.string().optional()
})

// ===================================================================================
// DTO Classes
// ===================================================================================

export class SendOtpDto extends createZodDto(SendOtpSchema) {}
export class VerifyOtpDto extends createZodDto(VerifyOtpSchema) {}

export class OtpVerificationSuccessResponseDto extends createZodDto(OtpVerificationSuccessResponseSchema) {}
export class OtpVerificationStepSuccessResponseDto extends createZodDto(OtpVerificationStepSuccessResponseSchema) {}
