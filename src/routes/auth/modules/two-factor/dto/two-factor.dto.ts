import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

// Setup 2FA DTOs
export const TwoFactorSetupSchema = z.object({})

export const TwoFactorSetupResponseSchema = z.object({
  secret: z.string(),
  uri: z.string()
})

// Confirm 2FA Setup DTOs
export const TwoFactorConfirmSetupSchema = z.object({
  totpCode: z
    .string()
    .min(6, { message: 'Mã TOTP phải có ít nhất 6 ký tự' })
    .max(6, { message: 'Mã TOTP tối đa 6 ký tự' })
})

export const TwoFactorConfirmSetupResponseSchema = z.object({
  message: z.string(),
  recoveryCodes: z.array(z.string())
})

// Verify 2FA DTOs
export const TwoFactorVerifySchema = z.object({
  code: z.string().min(6, { message: 'Mã xác thực phải có ít nhất 6 ký tự' }),
  rememberMe: z.boolean().optional().default(false)
})

export const TwoFactorVerifyResponseSchema = z.object({
  message: z.string()
})

// Disable 2FA DTOs
export const DisableTwoFactorSchema = z.object({
  code: z.string().min(6, { message: 'Mã xác thực phải có ít nhất 6 ký tự' }),
  method: z.enum(['TOTP', 'RECOVERY_CODE', 'PASSWORD']).optional()
})

export const DisableTwoFactorResponseSchema = z.object({
  message: z.string()
})

// Regenerate Recovery Codes DTOs
export const RegenerateRecoveryCodesSchema = z.object({
  code: z.string().min(6, { message: 'Mã TOTP phải có ít nhất 6 ký tự' }).max(6, { message: 'Mã TOTP tối đa 6 ký tự' })
})

export const RegenerateRecoveryCodesResponseSchema = z.object({
  message: z.string(),
  recoveryCodes: z.array(z.string())
})

// Create DTO classes
export class TwoFactorSetupDto extends createZodDto(TwoFactorSetupSchema) {}
export class TwoFactorSetupResponseDto extends createZodDto(TwoFactorSetupResponseSchema) {}
export class TwoFactorConfirmSetupDto extends createZodDto(TwoFactorConfirmSetupSchema) {}
export class TwoFactorConfirmSetupResponseDto extends createZodDto(TwoFactorConfirmSetupResponseSchema) {}
export class TwoFactorVerifyDto extends createZodDto(TwoFactorVerifySchema) {}
export class TwoFactorVerifyResponseDto extends createZodDto(TwoFactorVerifyResponseSchema) {}
export class DisableTwoFactorDto extends createZodDto(DisableTwoFactorSchema) {}
export class DisableTwoFactorResponseDto extends createZodDto(DisableTwoFactorResponseSchema) {}
export class RegenerateRecoveryCodesDto extends createZodDto(RegenerateRecoveryCodesSchema) {}
export class RegenerateRecoveryCodesResponseDto extends createZodDto(RegenerateRecoveryCodesResponseSchema) {}
