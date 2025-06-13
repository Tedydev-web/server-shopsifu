import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { VerificationNeededResponseSchema } from './auth-verification.dto'

// ===================================================================================
// Schemas for Request Bodies
// ===================================================================================

// --- Initiate Registration ---
export const InitiateRegistrationSchema = z.object({
  email: z.string().email('auth.error.validation.invalidEmailFormat')
})

// --- Complete Registration ---
export const CompleteRegistrationSchema = z.object({
  password: z
    .string()
    .min(8, 'auth.error.validation.passwordTooShort')
    .max(100, 'auth.error.validation.passwordTooLong'),
  confirmPassword: z.string(),
  firstName: z.string().min(1).max(100),
  lastName: z.string().min(1).max(100),
  username: z.string().min(3).max(100),
  phoneNumber: z.string().optional(),
  fingerprint: z.string().optional()
})

// --- Login ---
export const LoginSchema = z.object({
  email: z.string().email('auth.error.validation.invalidEmailFormat'),
  password: z
    .string()
    .min(1, 'auth.error.validation.passwordRequired') // Cannot be empty
    .max(100, 'auth.error.validation.passwordTooLong'),
  rememberMe: z.boolean().optional(),
  fingerprint: z.string().optional()
})

// --- Refresh Token ---
export const RefreshTokenSchema = z.object({
  refreshToken: z.string()
})

// --- Logout ---
export const LogoutSchema = z.object({})

// ===================================================================================
// Schemas for Response Data
// ===================================================================================

// --- Login ---
const LoginSuccessDataSchema = z.object({
  user: z.object({
    id: z.number(),
    username: z.string().nullable(),
    avatar: z.string().nullable(),
    isDeviceTrustedInSession: z.boolean()
  })
})
export const LoginSuccessResponseSchema = z.object({
  data: LoginSuccessDataSchema
})

// --- Refresh Token ---
export const RefreshTokenResponseSchema = z.object({})

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
export class LoginSuccessResponseDto extends createZodDto(LoginSuccessResponseSchema) {}
export class LoginVerificationNeededResponseDto extends createZodDto(VerificationNeededResponseSchema) {}
export class RefreshTokenResponseDto extends createZodDto(RefreshTokenResponseSchema) {}
