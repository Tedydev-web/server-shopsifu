import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { VerificationNeededResponseSchema } from '../../shared/dtos/verification.dto'

// ===================================================================================
// Schemas for Request Bodies
// ===================================================================================

export const TwoFactorVerifySchema = z.object({
  code: z.string().min(6, 'Mã xác thực phải có ít nhất 6 ký tự.').max(20, 'Mã xác thực không được vượt quá 20 ký tự.'),
  method: z.enum(['TOTP', 'RECOVERY']).optional()
})

// ===================================================================================
// Schemas for Response Data (to be wrapped by TransformInterceptor)
// ===================================================================================

/**
 * Dữ liệu trả về khi bắt đầu thiết lập 2FA.
 */
export const TwoFactorSetupDataSchema = z.object({
  secret: z.string(),
  uri: z.string()
})

/**
 * Dữ liệu trả về sau khi xác nhận 2FA thành công hoặc tạo lại mã.
 */
export const TwoFactorRecoveryCodesDataSchema = z.object({
  recoveryCodes: z.array(z.string())
})

// ===================================================================================
// DTO Classes
// ===================================================================================

// --- Request DTOs ---
export class TwoFactorVerifyDto extends createZodDto(TwoFactorVerifySchema) {}

// --- Response DTOs ---
export class TwoFactorSetupDataDto extends createZodDto(TwoFactorSetupDataSchema) {}
export class TwoFactorRecoveryCodesDataDto extends createZodDto(TwoFactorRecoveryCodesDataSchema) {}
export class VerificationNeededResponseDto extends createZodDto(VerificationNeededResponseSchema) {}
