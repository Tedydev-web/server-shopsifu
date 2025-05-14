import { TypeOfVerificationCode } from 'src/shared/constants/auth.constant'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { z } from 'zod'

export const RegisterBodySchema = UserSchema.pick({
  email: true,
  name: true,
  phoneNumber: true,
  password: true
})
  .extend({
    otpToken: z.string({ required_error: 'ERROR.OTP_TOKEN_REQUIRED' }),
    confirmPassword: z.string({ required_error: 'ERROR.PASSWORD_CONFIRMATION_REQUIRED' })
  })
  .strict()
  .refine((data) => data.password === data.confirmPassword, {
    message: 'ERROR.PASSWORD_CONFIRMATION_MISMATCH',
    path: ['confirmPassword']
  })

export const RegisterResSchema = UserSchema.omit({
  password: true,
  totpSecret: true
})

export const VerificationCodeSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  code: z.string().length(6),
  type: z.enum([
    TypeOfVerificationCode.REGISTER,
    TypeOfVerificationCode.FORGOT_PASSWORD,
    TypeOfVerificationCode.LOGIN,
    TypeOfVerificationCode.DISABLE_2FA
  ]),
  deviceId: z.number().nullable(),
  expiresAt: z.date(),
  createdAt: z.date()
})

export const SendOTPBodySchema = z
  .object({
    email: z.string().email({ message: 'ERROR.INVALID_EMAIL' }),
    type: z.enum(
      [
        TypeOfVerificationCode.REGISTER,
        TypeOfVerificationCode.FORGOT_PASSWORD,
        TypeOfVerificationCode.LOGIN,
        TypeOfVerificationCode.DISABLE_2FA
      ],
      { errorMap: () => ({ message: 'ERROR.INVALID_OTP_TYPE' }) }
    )
  })
  .strict()

export const LoginBodySchema = UserSchema.pick({
  email: true,
  password: true
})
  .extend({
    totpCode: z.string().length(6).optional(), // 2FA code
    code: z.string().length(6).optional() // Email OTP code
  })
  .strict()

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
  userId: z.number().nullable(),
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

export const DisableTwoFactorBodySchema = z
  .object({
    totpCode: z.string().length(6).optional(),
    code: z.string().length(6).optional()
  })
  .strict()
  .superRefine(({ totpCode, code }, ctx) => {
    // Nếu cả 2 đều có hoặc không có thì sẽ nhảy vào if
    if ((totpCode !== undefined) === (code !== undefined)) {
      ctx.addIssue({
        path: ['totpCode'],
        message: 'ERROR.EITHER_TOTP_OR_OTP_REQUIRED',
        code: 'custom'
      })
      ctx.addIssue({
        path: ['code'],
        message: 'ERROR.EITHER_TOTP_OR_OTP_REQUIRED',
        code: 'custom'
      })
    }
  })
export const TwoFactorSetupResSchema = z.object({
  secret: z.string(),
  uri: z.string()
})

export const OtpTokenSchema = z.object({
  id: z.number(),
  token: z.string(),
  userId: z.number().nullable(),
  email: z.string().email(),
  deviceId: z.number().nullable(),
  type: z.string(),
  expiresAt: z.date(),
  createdAt: z.date()
})

export const VerifyOTPBodySchema = z
  .object({
    email: z.string().email(),
    code: z.string().length(6),
    type: z.enum([TypeOfVerificationCode.REGISTER, TypeOfVerificationCode.FORGOT_PASSWORD])
  })
  .strict()

export const VerifyOTPResSchema = z.object({
  otpToken: z.string()
})

export const ResetPasswordBodySchema = z
  .object({
    email: z.string().email(),
    otpToken: z.string(),
    newPassword: z.string().min(6),
    confirmNewPassword: z.string()
  })
  .strict()
  .refine((data) => data.newPassword === data.confirmNewPassword, {
    message: 'ERROR.PASSWORD_CONFIRMATION_MISMATCH',
    path: ['confirmNewPassword']
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
export type DisableTwoFactorBodyType = z.infer<typeof DisableTwoFactorBodySchema>
export type TwoFactorSetupResType = z.infer<typeof TwoFactorSetupResSchema>
export type OtpTokenType = z.infer<typeof OtpTokenSchema>
export type VerifyOTPBodyType = z.infer<typeof VerifyOTPBodySchema>
export type VerifyOTPResType = z.infer<typeof VerifyOTPResSchema>
export type ResetPasswordBodyType = z.infer<typeof ResetPasswordBodySchema>
