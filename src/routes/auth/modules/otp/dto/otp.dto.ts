import { createZodDto } from 'nestjs-zod'
import { TypeOfVerificationCode } from 'src/routes/auth/constants/auth.constants'
import { z } from 'zod'

// Send OTP DTOs
export const SendOtpSchema = z.object({
  email: z.string().email({ message: 'Email không hợp lệ' }),
  type: z.nativeEnum(TypeOfVerificationCode, {
    errorMap: () => ({ message: 'Loại mã xác thực không hợp lệ' })
  })
})

export const SendOtpResponseSchema = z.object({
  message: z.string()
})

// Verify OTP DTOs
export const VerifyOtpSchema = z.object({
  code: z.string().min(6, { message: 'Mã OTP phải có ít nhất 6 ký tự' }).max(6, { message: 'Mã OTP tối đa 6 ký tự' }),
  rememberMe: z.boolean().optional().default(false)
})

export const VerifyOtpResponseSchema = z.object({
  message: z.string()
})

export const VerifyOtpWithRedirectSchema = z.object({
  message: z.string(),
  redirectUrl: z.string().optional()
})

// DTO classes
export class SendOtpDto extends createZodDto(SendOtpSchema) {}
export class SendOtpResponseDto extends createZodDto(SendOtpResponseSchema) {}
export class VerifyOtpDto extends createZodDto(VerifyOtpSchema) {}
export class VerifyOtpResponseDto extends createZodDto(VerifyOtpResponseSchema) {}
export class VerifyOtpWithRedirectDto extends createZodDto(VerifyOtpWithRedirectSchema) {}
