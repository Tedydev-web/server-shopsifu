import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

// ===================================================================================
// Schemas for API Payloads (Request Bodies & URL Params)
// ===================================================================================

// --- Get Google URL ---
export const GoogleAuthUrlQuerySchema = z.object({
  action: z.enum(['login', 'register', 'link']).default('login'),
  redirectUrl: z.string().url().optional()
})

// --- Google Callback ---
export const GoogleCallbackQuerySchema = z.object({
  code: z.string(),
  state: z.string(),
  error: z.string().optional()
})

// --- Verify/Complete Actions ---
export const VerifyAuthenticationSchema = z.object({
  password: z.string().optional() // For completing link for users with existing password
})

// ===================================================================================
// Schemas for Response Data (to be wrapped by TransformInterceptor)
// ===================================================================================

// --- Get Google URL ---
export const GoogleAuthUrlDataSchema = z.object({
  url: z.string().url()
})

// --- Callback -> Linking Required ---
export const AccountLinkingRequiredDataSchema = z.object({
  needsLinking: z.literal(true).default(true),
  existingUserEmail: z.string().email(),
  googleEmail: z.string().email(),
  googleName: z.string().nullable(),
  googleAvatar: z.string().nullable()
})

// ===================================================================================
// DTO Classes
// ===================================================================================

// --- Request DTOs ---
export class GoogleAuthUrlQueryDto extends createZodDto(GoogleAuthUrlQuerySchema) {}
export class GoogleCallbackQueryDto extends createZodDto(GoogleCallbackQuerySchema) {}
export class VerifyAuthenticationDto extends createZodDto(VerifyAuthenticationSchema) {}

// --- Response DTOs ---
export class GoogleAuthUrlDataDto extends createZodDto(GoogleAuthUrlDataSchema) {}
export class AccountLinkingRequiredDataDto extends createZodDto(AccountLinkingRequiredDataSchema) {}
