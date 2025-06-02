import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

// Google Auth DTOs
export const GoogleAuthUrlQuerySchema = z.object({
  flow: z.enum(['login', 'register', 'link']).optional()
})

export const GoogleAuthUrlResponseSchema = z.object({
  url: z.string()
})

export const GoogleCallbackQuerySchema = z.object({
  code: z.string(),
  state: z.string(),
  error: z.string().optional()
})

export const GoogleCallbackResponseSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  role: z.string(),
  isDeviceTrustedInSession: z.boolean(),
  userProfile: z
    .object({
      firstName: z.string().nullable(),
      lastName: z.string().nullable(),
      username: z.string().nullable(),
      avatar: z.string().nullable()
    })
    .nullable()
})

// Google Account Linking DTOs
export const LinkGoogleAccountSchema = z.object({
  googleIdToken: z.string()
})

export const LinkGoogleAccountResponseSchema = z.object({
  message: z.string()
})

export const PendingLinkDetailsSchema = z.object({
  existingUserId: z.number(),
  existingUserEmail: z.string(),
  googleId: z.string(),
  googleEmail: z.string(),
  googleName: z.string().nullable(),
  googleAvatar: z.string().nullable()
})

export const CompleteLinkSchema = z.object({
  password: z.string()
})

export const CompleteLinkResponseSchema = GoogleCallbackResponseSchema

export const CancelLinkSchema = z.object({})

export const CancelLinkResponseSchema = z.object({
  message: z.string()
})

// Create DTO classes
export class GoogleAuthUrlQueryDto extends createZodDto(GoogleAuthUrlQuerySchema) {}
export class GoogleAuthUrlResponseDto extends createZodDto(GoogleAuthUrlResponseSchema) {}
export class GoogleCallbackQueryDto extends createZodDto(GoogleCallbackQuerySchema) {}
export class GoogleCallbackResponseDto extends createZodDto(GoogleCallbackResponseSchema) {}
export class LinkGoogleAccountDto extends createZodDto(LinkGoogleAccountSchema) {}
export class LinkGoogleAccountResponseDto extends createZodDto(LinkGoogleAccountResponseSchema) {}
export class PendingLinkDetailsDto extends createZodDto(PendingLinkDetailsSchema) {}
export class CompleteLinkDto extends createZodDto(CompleteLinkSchema) {}
export class CompleteLinkResponseDto extends createZodDto(CompleteLinkResponseSchema) {}
export class CancelLinkDto extends createZodDto(CancelLinkSchema) {}
export class CancelLinkResponseDto extends createZodDto(CancelLinkResponseSchema) {}
