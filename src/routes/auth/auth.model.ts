import { TwoFactorMethodType, TypeOfVerificationCode } from './constants/auth.constants'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { z } from 'zod'
import { PasswordsDoNotMatchException, InvalidCodeFormatException } from './auth.error'

export const RegisterBodySchema = UserSchema.pick({
  email: true,
  password: true,
  name: true,
  phoneNumber: true
})
  .extend({
    confirmPassword: z.string().min(6).max(100),
    otpToken: z.string()
  })
  .strict()
  .superRefine(({ confirmPassword, password }, ctx) => {
    if (confirmPassword !== password) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: PasswordsDoNotMatchException.message,
        path: ['confirmPassword']
      })
    }
  })

export const RegisterResSchema = UserSchema.omit({
  password: true,
  twoFactorSecret: true
})

export const VerificationCodeSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  code: z.string().length(6),
  type: z.nativeEnum(TypeOfVerificationCode),
  expiresAt: z.date(),
  createdAt: z.date()
})

export const SendOTPBodySchema = VerificationCodeSchema.pick({
  email: true,
  type: true
}).strict()

export const LoginBodySchema = UserSchema.pick({
  email: true,
  password: true
})
  .extend({
    rememberMe: z.boolean().optional().default(false)
  })
  .strict()

export const LoginResSchema = z.object({
  userId: z.number(),
  email: z.string().email(),
  name: z.string(),
  role: z.string(),
  askToTrustDevice: z.boolean().optional()
})

export const LoginSessionResSchema = z.object({
  message: z.string(),
  loginSessionToken: z.string(),
  twoFactorMethod: z.nativeEnum(TwoFactorMethodType)
})

export const VerifyCodeBodySchema = z
  .object({
    email: z.string().email(),
    code: z.string().length(6),
    type: z.nativeEnum(TypeOfVerificationCode)
  })
  .strict()

export const VerifyCodeResSchema = z.object({
  otpToken: z.string()
})

export const RefreshTokenBodySchema = z.object({}).strict()

export const AccessTokenResSchema = z.object({
  accessToken: z.string()
})

export const RefreshTokenResSchema = AccessTokenResSchema

export const DeviceSchema = z.object({
  id: z.number(),
  userId: z.number(),
  userAgent: z.string(),
  ip: z.string(),
  lastActive: z.date(),
  createdAt: z.date(),
  isActive: z.boolean(),
  isTrusted: z.boolean().optional()
})

export const RefreshTokenSchema = z.object({
  token: z.string(),
  userId: z.number(),
  deviceId: z.number(),
  expiresAt: z.date(),
  createdAt: z.date()
})

export const RoleSchema = z.object({
  id: z.number(),
  name: z.string(),
  description: z.string(),
  isActive: z.boolean(),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export const LogoutBodySchema = z.object({}).strict()

export const GoogleAuthStateSchema = DeviceSchema.pick({
  userAgent: true,
  ip: true
}).extend({
  rememberMe: z.boolean().optional()
})

export const GetAuthorizationUrlResSchema = z.object({
  url: z.string().url()
})

export const ResetPasswordBodySchema = z
  .object({
    email: z.string().email(),
    otpToken: z.string(),
    newPassword: z.string().min(6).max(100),
    confirmNewPassword: z.string().min(6).max(100)
  })
  .strict()
  .superRefine(({ confirmNewPassword, newPassword }, ctx) => {
    if (confirmNewPassword !== newPassword) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: PasswordsDoNotMatchException.message,
        path: ['confirmNewPassword']
      })
    }
  })

export const DisableTwoFactorBodySchema = z
  .object({
    type: z.enum([TwoFactorMethodType.TOTP, TwoFactorMethodType.OTP, TwoFactorMethodType.RECOVERY] as const),
    code: z.string().min(6)
  })
  .strict()
export const TwoFactorSetupResSchema = z.object({
  secret: z.string(),
  uri: z.string(),
  setupToken: z.string()
})

export const TwoFactorConfirmSetupBodySchema = z
  .object({
    setupToken: z.string(),
    totpCode: z.string().length(6)
  })
  .strict()

export const TwoFactorConfirmSetupResSchema = z.object({
  message: z.string(),
  recoveryCodes: z.array(z.string())
})

export const TwoFactorVerifyBodySchema = z
  .object({
    loginSessionToken: z.string(),
    type: z.enum([TwoFactorMethodType.TOTP, TwoFactorMethodType.OTP, TwoFactorMethodType.RECOVERY]),
    code: z.string()
  })
  .strict()
  .refine(
    (data) => {
      if (data.code.length === 0) return false

      if (data.type === TwoFactorMethodType.TOTP || data.type === TwoFactorMethodType.OTP) {
        return data.code.length === 6
      } else if (data.type === TwoFactorMethodType.RECOVERY) {
        return data.code.length >= 10
      }
      return true
    },
    {
      message: InvalidCodeFormatException.message,
      path: ['code']
    }
  )

export const UserProfileResSchema = z.object({
  userId: z.number(),
  email: z.string().email(),
  name: z.string(),
  role: z.string(),
  isDeviceTrustedInSession: z.boolean(),
  currentDeviceId: z.number().int().positive()
})

export type RegisterBodyType = z.infer<typeof RegisterBodySchema>
export type RegisterResType = z.infer<typeof RegisterResSchema>
export type VerificationCodeType = z.infer<typeof VerificationCodeSchema>
export type SendOTPBodyType = z.infer<typeof SendOTPBodySchema>
export type LoginBodyType = z.infer<typeof LoginBodySchema>
export type LoginResType = z.infer<typeof LoginResSchema>
export type RefreshTokenType = z.infer<typeof RefreshTokenSchema>
export type RefreshTokenBodyType = z.infer<typeof RefreshTokenBodySchema>
export type RefreshTokenResType = z.infer<typeof RefreshTokenResSchema>
export type DeviceType = z.infer<typeof DeviceSchema>
export type RoleType = z.infer<typeof RoleSchema>
export type LogoutBodyType = RefreshTokenBodyType
export type GoogleAuthStateType = z.infer<typeof GoogleAuthStateSchema>
export type GetAuthorizationUrlResType = z.infer<typeof GetAuthorizationUrlResSchema>
export type ResetPasswordBodyType = z.infer<typeof ResetPasswordBodySchema>
export type DisableTwoFactorBodyType = z.infer<typeof DisableTwoFactorBodySchema>
export type TwoFactorSetupResType = z.infer<typeof TwoFactorSetupResSchema>
export type TwoFactorConfirmSetupBodyType = z.infer<typeof TwoFactorConfirmSetupBodySchema>
export type TwoFactorConfirmSetupResType = z.infer<typeof TwoFactorConfirmSetupResSchema>
export type VerifyCodeBodyType = z.infer<typeof VerifyCodeBodySchema>
export type VerifyCodeResType = z.infer<typeof VerifyCodeResSchema>
export type LoginSessionResType = z.infer<typeof LoginSessionResSchema>
export type TwoFactorVerifyBodyType = z.infer<typeof TwoFactorVerifyBodySchema>
export type UserProfileResType = z.infer<typeof UserProfileResSchema>
export type AccessTokenResType = z.infer<typeof AccessTokenResSchema>

// Schema for successful token refresh without returning the token in body
export const RefreshTokenSuccessResSchema = z.object({
  message: z.string()
})

// Schemas for new endpoints
export const TrustDeviceBodySchema = z
  .object({
    // deviceId: z.number().int().positive() // Removed deviceId
    // Không cần userId ở body vì sẽ lấy từ active user
    // Body sẽ rỗng, chỉ cần endpoint được gọi với AT hợp lệ
  })
  .strict()

export const RememberMeBodySchema = z
  .object({
    rememberMe: z.boolean()
    // Không cần userId hay deviceId ở body vì sẽ lấy từ active user và refresh token
  })
  .strict()

export type TrustDeviceBodyType = z.infer<typeof TrustDeviceBodySchema>
export type RememberMeBodyType = z.infer<typeof RememberMeBodySchema>

export type RefreshTokenSuccessResType = z.infer<typeof RefreshTokenSuccessResSchema>

// Schema for new device management endpoints
export const UntrustDeviceBodySchema = z.object({}).strict() // Empty body

export const LogoutFromDeviceBodySchema = z
  .object({
    deviceId: z.number().int().positive()
  })
  .strict()

export type UntrustDeviceBodyType = z.infer<typeof UntrustDeviceBodySchema>
export type LogoutFromDeviceBodyType = z.infer<typeof LogoutFromDeviceBodySchema>
