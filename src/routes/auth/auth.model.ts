import { TypeOfVerificationCode, TypeOfOtpToken } from 'src/shared/constants/auth.constant'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { PasswordErrorMessages } from './error.model'
import { z } from 'zod'

export const RegisterBodySchema = UserSchema.pick({
  email: true,
  password: true,
  name: true,
  phoneNumber: true
})
  .extend({
    confirmPassword: z.string().min(8, PasswordErrorMessages.MIN_LENGTH).max(100, PasswordErrorMessages.MAX_LENGTH),
    code: z.string().length(6)
  })
  .strict()
  .superRefine(({ confirmPassword, password }, ctx) => {
    if (confirmPassword !== password) {
      ctx.addIssue({
        code: 'custom',
        message: PasswordErrorMessages.MATCH,
        path: ['confirmPassword']
      })
    }
  })
  .transform(({ email, ...rest }) => ({
    email: email.toLowerCase(),
    ...rest
  }))

export const RegisterResSchema = UserSchema.omit({
  password: true,
  totpSecret: true
})

export const VerificationCodeSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  code: z.string().length(6),
  salt: z.string(),
  attempts: z.number().default(0),
  type: z.enum([
    TypeOfVerificationCode.REGISTER,
    TypeOfVerificationCode.FORGOT_PASSWORD,
    TypeOfVerificationCode.LOGIN,
    TypeOfVerificationCode.DISABLE_2FA
  ]),
  expiresAt: z.date(),
  createdAt: z.date()
})

export const SendOTPBodySchema = VerificationCodeSchema.pick({
  email: true,
  type: true
})
  .strict()
  .transform(({ email, ...rest }) => ({
    email: email.toLowerCase(),
    ...rest
  }))

export const LoginBodySchema = UserSchema.pick({
  email: true,
  password: true
})
  .extend({
    totpCode: z.string().length(6).optional(), // 2FA code
    code: z.string().length(6).optional() // Email OTP code
  })
  .strict()
  .transform(({ email, ...rest }) => ({
    email: email.toLowerCase(),
    ...rest
  }))

export const LoginResSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string()
})

export const RefreshTokenBodySchema = z
  .object({
    refreshToken: z.string()
  })
  .strict()

export const RefreshTokenResSchema = LoginResSchema

export const DeviceSchema = z.object({
  id: z.number(),
  userId: z.number(),
  userAgent: z.string(),
  ip: z.string(),
  lastActive: z.date(),
  createdAt: z.date(),
  isActive: z.boolean()
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

export const LogoutBodySchema = RefreshTokenBodySchema

export const GoogleAuthStateSchema = DeviceSchema.pick({
  userAgent: true,
  ip: true
})

export const GetAuthorizationUrlResSchema = z.object({
  url: z.string().url()
})

export const VerifyCodeBodySchema = z
  .object({
    email: z.string().email(),
    code: z.string().length(6),
    type: z.enum([
      TypeOfVerificationCode.REGISTER,
      TypeOfVerificationCode.FORGOT_PASSWORD,
      TypeOfVerificationCode.LOGIN,
      TypeOfVerificationCode.DISABLE_2FA
    ])
  })
  .strict()
  .transform(({ email, ...rest }) => ({
    email: email.toLowerCase(),
    ...rest
  }))

export const VerifyCodeResponseSchema = z
  .object({
    token: z.string(),
    expiresAt: z.date()
  })
  .strict()

export const ResetPasswordBodySchema = z
  .object({
    token: z.string(),
    newPassword: z
      .string()
      .min(8, PasswordErrorMessages.MIN_LENGTH)
      .max(100, PasswordErrorMessages.MAX_LENGTH)
      .regex(/[A-Z]/, PasswordErrorMessages.UPPERCASE)
      .regex(/[a-z]/, PasswordErrorMessages.LOWERCASE)
      .regex(/[0-9]/, PasswordErrorMessages.NUMBER)
      .regex(/[^A-Za-z0-9]/, PasswordErrorMessages.SPECIAL_CHAR),
    confirmNewPassword: z.string().min(8).max(100)
  })
  .strict()
  .superRefine(({ confirmNewPassword, newPassword }, ctx) => {
    if (confirmNewPassword !== newPassword) {
      ctx.addIssue({
        code: 'custom',
        message: PasswordErrorMessages.MATCH,
        path: ['confirmNewPassword']
      })
    }
  })

export const DisableTwoFactorBodySchema = z
  .object({
    totpCode: z.string().length(6).optional(),
    code: z.string().length(6).optional()
  })
  .strict()
  .superRefine(({ totpCode, code }, ctx) => {
    const message = 'Bạn phải cung cấp mã xác thực 2FA hoặc mã OTP. Không được cung cấp cả 2'
    // Nếu cả 2 đều có hoặc không có thì sẽ nhảy vào if
    if ((totpCode !== undefined) === (code !== undefined)) {
      ctx.addIssue({
        path: ['totpCode'],
        message,
        code: 'custom'
      })
      ctx.addIssue({
        path: ['code'],
        message,
        code: 'custom'
      })
    }
  })

export const TwoFactorSetupResSchema = z.object({
  secret: z.string(),
  url: z.string()
})

export const OtpTokenSchema = z.object({
  token: z.string(),
  userId: z.number(),
  deviceId: z.number(),
  type: z.enum([TypeOfOtpToken.FORGOT_PASSWORD, TypeOfOtpToken.EMAIL_VERIFICATION, TypeOfOtpToken.CHANGE_EMAIL]),
  expiresAt: z.date(),
  createdAt: z.date(),
  device: DeviceSchema.optional()
})

export type RegisterBodyType = z.infer<typeof RegisterBodySchema>
export type RegisterResType = z.infer<typeof RegisterResSchema>
export type VerificationCodeType = z.infer<typeof VerificationCodeSchema>
export type SendOTPBodyType = z.infer<typeof SendOTPBodySchema>
export type LoginBodyType = z.infer<typeof LoginBodySchema>
export type LoginResType = z.infer<typeof LoginResSchema>
export type RefreshTokenType = z.infer<typeof RefreshTokenSchema>
export type RefreshTokenBodyType = z.infer<typeof RefreshTokenBodySchema>
export type RefreshTokenResType = LoginResType
export type DeviceType = z.infer<typeof DeviceSchema>
export type RoleType = z.infer<typeof RoleSchema>
export type LogoutBodyType = RefreshTokenBodyType
export type GoogleAuthStateType = z.infer<typeof GoogleAuthStateSchema>
export type GetAuthorizationUrlResType = z.infer<typeof GetAuthorizationUrlResSchema>
export type VerifyCodeBodyType = z.infer<typeof VerifyCodeBodySchema>
export type VerifyCodeResponseType = z.infer<typeof VerifyCodeResponseSchema>
export type ResetPasswordBodyType = z.infer<typeof ResetPasswordBodySchema>
export type DisableTwoFactorBodyType = z.infer<typeof DisableTwoFactorBodySchema>
export type TwoFactorSetupResType = z.infer<typeof TwoFactorSetupResSchema>
export type OtpTokenType = z.infer<typeof OtpTokenSchema>
