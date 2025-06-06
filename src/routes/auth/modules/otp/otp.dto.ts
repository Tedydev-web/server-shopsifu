import { createZodDto } from 'nestjs-zod'
import { TypeOfVerificationCode } from 'src/routes/auth/shared/constants/auth.constants'
import { z } from 'zod'

// ===================================================================================
// Schemas for Request Bodies
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
// Schemas for Response Data (to be wrapped by TransformInterceptor)
// ===================================================================================

// For a successful verification that results in login/session creation
export const OtpVerificationSuccessResponseSchema = z.object({
  user: z.any(),
  tokens: z
    .object({
      accessToken: z.string(),
      refreshToken: z.string()
    })
    .optional()
})

// For a successful verification that enables the next step (e.g., registration completion)
export const OtpVerificationStepSuccessResponseSchema = z.object({
  slt: z.string().optional()
  // Add other relevant fields if necessary
})

// ===================================================================================
// DTO Classes
// ===================================================================================

export class SendOtpDto extends createZodDto(SendOtpSchema) {}
export class VerifyOtpDto extends createZodDto(VerifyOtpSchema) {}

export class OtpVerificationSuccessResponseDto extends createZodDto(OtpVerificationSuccessResponseSchema) {}
export class OtpVerificationStepSuccessResponseDto extends createZodDto(OtpVerificationStepSuccessResponseSchema) {}
