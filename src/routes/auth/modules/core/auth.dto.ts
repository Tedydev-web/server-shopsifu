import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { UserAuthResponseSchema, CompleteRegistrationSchema } from 'src/routes/auth/shared/schemas'

// ===================================================================================
// Schemas for Request Bodies
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
// Schemas for Response Data (to be wrapped by TransformInterceptor)
// ===================================================================================

// --- Login ---
// Schema for the data part of the response when further verification is needed.
export const LoginVerificationNeededResponseSchema = z.object({
  sltToken: z.string().optional(),
  verificationType: z.enum(['OTP', '2FA']).optional()
})

// --- Refresh Token ---
// Schema for the data part of the response when a token is refreshed.
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
// Note: These DTOs now represent the `data` field in the final API response.
export class LoginVerificationNeededResponseDto extends createZodDto(LoginVerificationNeededResponseSchema) {}
export class RefreshTokenResponseDto extends createZodDto(RefreshTokenResponseSchema) {}
