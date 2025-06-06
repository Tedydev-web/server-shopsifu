import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { UserProfileSchema as SharedUserProfileSchema } from 'src/shared/dtos/user.dto'

// Google Auth URL Query DTOs
export const GoogleAuthUrlQuerySchema = z.object({
  // Thay flow bằng action để thống nhất với cấu trúc yêu cầu
  action: z.enum(['login', 'register', 'link']).default('login'),
  // Thêm redirectUrl tuỳ chọn để client có thể chỉ định URL chuyển hướng sau khi hoàn tất
  redirectUrl: z.string().url().optional()
})

export const GoogleAuthUrlResponseSchema = z.object({
  status: z.literal('success'),
  data: z.object({
    url: z.string().min(1, { message: 'URL không được để trống' })
  })
})

// Google Callback Query DTOs
export const GoogleCallbackQuerySchema = z.object({
  code: z.string(),
  state: z.string(),
  error: z.string().optional()
})

// User Profile Schema đã được pick từ shared model
const PickedGoogleUserProfileSchema = SharedUserProfileSchema.pick({
  firstName: true,
  lastName: true,
  username: true,
  avatar: true
})

// Google Login/Register Response DTOs
export const GoogleAuthResponseSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  roleName: z.string(),
  isDeviceTrustedInSession: z.boolean(),
  userProfile: PickedGoogleUserProfileSchema.nullable()
})

// Two Factor Auth Required Response Schema
export const TwoFactorRequiredResponseSchema = z.object({
  status: z.literal('two_factor_required'),
  data: z.object({
    requiresTwoFactorAuth: z.literal(true),
    twoFactorMethod: z.enum(['TOTP', 'OTP', 'RECOVERY']).optional(),
    message: z.string()
  })
})

// Device Verification Required Response Schema
export const DeviceVerificationRequiredResponseSchema = z.object({
  status: z.literal('device_verification_required'),
  data: z.object({
    requiresDeviceVerification: z.literal(true),
    message: z.string()
  })
})

// Account Linking Required Response Schema
export const AccountLinkingRequiredResponseSchema = z.object({
  status: z.literal('linking_required'),
  data: z.object({
    needsLinking: z.literal(true),
    existingUserId: z.number(),
    existingUserEmail: z.string().email(),
    googleId: z.string(),
    googleEmail: z.string().email(),
    googleName: z.string().nullable(),
    googleAvatar: z.string().nullable(),
    message: z.string()
  })
})

// Error Response Schema
export const GoogleAuthErrorResponseSchema = z.object({
  status: z.literal('error'),
  error: z.object({
    errorCode: z.string(),
    errorMessage: z.string(),
    redirectToError: z.literal(true)
  })
})

// Success Response Schema
export const GoogleAuthSuccessResponseSchema = z.object({
  status: z.literal('success'),
  user: GoogleAuthResponseSchema
})

// Google Account Linking DTOs
export const LinkGoogleAccountSchema = z.object({
  googleIdToken: z.string()
})

export const LinkGoogleAccountResponseSchema = z.object({
  message: z.string()
})

// Unlinking Google Account DTOs
export const UnlinkGoogleAccountSchema = z.object({
  // Không cần tham số
})

export const UnlinkGoogleAccountResponseSchema = z.object({
  message: z.string(),
  success: z.boolean()
})

// Verify Unlink Request DTOs
export const InitiateUnlinkSchema = z.object({
  // Không cần tham số
})

export const InitiateUnlinkResponseSchema = z.object({
  message: z.string()
})

export const VerifyUnlinkSchema = z.object({
  // Có thể là OTP hoặc password tùy vào phương thức xác thực
  verificationCode: z.string().optional(),
  password: z.string().optional()
})

export const VerifyUnlinkResponseSchema = z.object({
  message: z.string(),
  success: z.boolean()
})

// Pending Link DTOs
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

export const CompleteLinkResponseSchema = z.object({
  status: z.enum(['success', 'error']),
  message: z.string(),
  user: GoogleAuthResponseSchema.optional()
})

export const CancelLinkSchema = z.object({})

export const CancelLinkResponseSchema = z.object({
  message: z.string()
})

// Verify Authentication Schemas
export const VerifyAuthenticationSchema = z.object({
  purpose: z.enum(['LINK_ACCOUNT', 'UNLINK_GOOGLE_ACCOUNT']),
  sltToken: z.string().optional(),
  code: z.string().optional(),
  password: z.string().optional()
})

export const VerifyAuthenticationResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  user: GoogleAuthResponseSchema.optional()
})

// Create DTO classes
export class GoogleAuthUrlQueryDto extends createZodDto(GoogleAuthUrlQuerySchema) {}
export class GoogleAuthUrlResponseDto extends createZodDto(GoogleAuthUrlResponseSchema) {}
export class GoogleCallbackQueryDto extends createZodDto(GoogleCallbackQuerySchema) {}
export class GoogleAuthResponseDto extends createZodDto(GoogleAuthResponseSchema) {}

// Tách các DTO riêng biệt cho từng trường hợp response từ callback
export class GoogleAuthSuccessResponseDto extends createZodDto(GoogleAuthSuccessResponseSchema) {}
export class TwoFactorRequiredResponseDto extends createZodDto(TwoFactorRequiredResponseSchema) {}
export class DeviceVerificationRequiredResponseDto extends createZodDto(DeviceVerificationRequiredResponseSchema) {}
export class AccountLinkingRequiredResponseDto extends createZodDto(AccountLinkingRequiredResponseSchema) {}
export class GoogleAuthErrorResponseDto extends createZodDto(GoogleAuthErrorResponseSchema) {}

// Type union cho response từ callback
export type GoogleCallbackResponseDto =
  | GoogleAuthSuccessResponseDto
  | TwoFactorRequiredResponseDto
  | DeviceVerificationRequiredResponseDto
  | AccountLinkingRequiredResponseDto
  | GoogleAuthErrorResponseDto

export class LinkGoogleAccountDto extends createZodDto(LinkGoogleAccountSchema) {}
export class LinkGoogleAccountResponseDto extends createZodDto(LinkGoogleAccountResponseSchema) {}
export class UnlinkGoogleAccountDto extends createZodDto(UnlinkGoogleAccountSchema) {}
export class UnlinkGoogleAccountResponseDto extends createZodDto(UnlinkGoogleAccountResponseSchema) {}
export class InitiateUnlinkDto extends createZodDto(InitiateUnlinkSchema) {}
export class InitiateUnlinkResponseDto extends createZodDto(InitiateUnlinkResponseSchema) {}
export class VerifyUnlinkDto extends createZodDto(VerifyUnlinkSchema) {}
export class VerifyUnlinkResponseDto extends createZodDto(VerifyUnlinkResponseSchema) {}

export class PendingLinkDetailsDto extends createZodDto(PendingLinkDetailsSchema) {}
export class CompleteLinkDto extends createZodDto(CompleteLinkSchema) {}
export class CompleteLinkResponseDto extends createZodDto(CompleteLinkResponseSchema) {}
export class CancelLinkDto extends createZodDto(CancelLinkSchema) {}
export class CancelLinkResponseDto extends createZodDto(CancelLinkResponseSchema) {}

// Thêm DTOs cho xác thực thống nhất
export class VerifyAuthenticationDto extends createZodDto(VerifyAuthenticationSchema) {}
export class VerifyAuthenticationResponseDto extends createZodDto(VerifyAuthenticationResponseSchema) {}

// Thêm union type cho verifyAuthentication response
export type VerifyAuthenticationResponseUnion =
  | VerifyAuthenticationResponseDto
  | PendingLinkDetailsDto
  | CancelLinkResponseDto
