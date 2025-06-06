import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

// ===================================================================================
// Schemas for Request Bodies
// ===================================================================================

export const TwoFactorVerifySchema = z.object({
  code: z.string().min(6).max(6)
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

/**
 * Dữ liệu trả về khi cần xác minh (response từ /setup, /disable, etc.).
 */
export const VerificationNeededResponseSchema = z.object({
  requiresAdditionalVerification: z.literal(true).default(true),
  verificationType: z.enum(['2FA', 'OTP']).optional()
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
