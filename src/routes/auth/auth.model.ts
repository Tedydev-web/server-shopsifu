import { TwoFactorMethodType, TypeOfVerificationCode } from './constants/auth.constants'
import { UserStatus } from '@prisma/client'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { UserProfileSchema } from 'src/shared/models/user-profile.model'
import { MessageResSchema } from 'src/shared/models/response.model'
import { z } from 'zod'

export const RegisterBodySchema = z
  .object({
    email: z.string().email('validation.email.invalid').max(100, 'validation.string.max.100'),
    password: z.string().min(8, 'validation.password.min.8').max(100, 'validation.string.max.100'),
    confirmPassword: z.string().min(8, 'validation.password.min.8').max(100, 'validation.string.max.100'),
    firstName: z.string().min(1, 'validation.string.min.1').max(50, 'validation.string.max.50'),
    lastName: z.string().min(1, 'validation.string.min.1').max(50, 'validation.string.max.50'),
    username: z
      .string()
      .min(3, 'validation.username.min.3')
      .max(30, 'validation.username.max.30')
      .regex(/^[a-zA-Z0-9_.]+$/, 'validation.username.invalidFormat')
      .optional()
      .nullable(),
    phoneNumber: z
      .string()
      .min(10, 'validation.phoneNumber.min.10')
      .max(15, 'validation.phoneNumber.max.15')
      .optional()
      .nullable()
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'error.Auth.Password.PasswordsDoNotMatch',
    path: ['confirmPassword']
  })

export const RegisterResSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  googleId: z.string().nullable().optional(),
  status: z.nativeEnum(UserStatus),
  roleId: z.number(),
  roleName: z.string().optional(),
  twoFactorEnabled: z.boolean(),
  twoFactorMethod: z.nativeEnum(TwoFactorMethodType).nullable().optional(),
  twoFactorVerifiedAt: z.date().nullable().optional(),
  isEmailVerified: z.boolean(),
  pendingEmail: z.string().email().nullable().optional(),
  emailVerificationToken: z.string().nullable().optional(),
  emailVerificationTokenExpiresAt: z.date().nullable().optional(),
  emailVerificationSentAt: z.date().nullable().optional(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
  deletedAt: z.date().nullable().optional(),
  createdById: z.number().nullable().optional(),
  updatedById: z.number().nullable().optional(),
  deletedById: z.number().nullable().optional(),
  userProfile: UserProfileSchema.pick({
    firstName: true,
    lastName: true,
    avatar: true,
    username: true,
    phoneNumber: true
  }).nullable()
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
})

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
  role: z.string(),
  askToTrustDevice: z.boolean().optional(),
  userProfile: UserProfileSchema.pick({ firstName: true, lastName: true, avatar: true, username: true })
    .nullable()
    .optional()
})

export const LoginSessionResSchema = z.object({
  message: z.string(),
  twoFactorMethod: z.nativeEnum(TwoFactorMethodType)
})

export const VerifyCodeBodySchema = z
  .object({
    code: z.string().length(6, 'validation.otp.length')
  })
  .strict()

export const VerifyCodeResSchema = MessageResSchema

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
  rememberMe: z.boolean().optional(),
  flow: z.string().optional(),
  userIdIfLinking: z.number().optional()
})

export const GetAuthorizationUrlResSchema = z.object({
  url: z.string().url()
})

export const ResetPasswordBodySchema = z.object({
  email: z.string().email('validation.email.invalid').max(100, 'validation.string.max.100'),
  newPassword: z.string().min(8, 'validation.password.min.8').max(100, 'validation.string.max.100')
})

export const DisableTwoFactorBodySchema = z
  .object({
    password: z.string().min(8, 'validation.password.min.8').optional(),
    code: z.string().length(6, 'validation.otp.length').optional(),
    recoveryCode: z.string().optional()
  })
  .refine(
    (data) => {
      const providedMethods = [data.password, data.code, data.recoveryCode].filter(Boolean).length
      return providedMethods === 1
    },
    {
      message: 'validation.2fa.disable.oneMethodRequired',

      path: ['_error']
    }
  )

export const TwoFactorSetupResSchema = z.object({
  secret: z.string(),
  uri: z.string()
})

export const TwoFactorConfirmSetupBodySchema = z
  .object({
    totpCode: z.string().length(6, 'validation.otp.length')
  })
  .strict()

export const TwoFactorConfirmSetupResSchema = z.object({
  message: z.string(),
  recoveryCodes: z.array(z.string())
})

export const TwoFactorVerifyBodySchema = z
  .object({
    email: z.string().email().optional(),
    code: z.string().length(6).optional(),
    recoveryCode: z.string().min(10).optional(),
    rememberMe: z.boolean().optional().default(false)
  })
  .strict()
  .superRefine((data, ctx) => {
    if (!data.code && !data.recoveryCode) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Either code or recoveryCode must be provided.',
        path: ['code']
      })
    }
    if (data.code && data.recoveryCode) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Provide either code or recoveryCode, not both.',
        path: ['code']
      })
    }
  })

export const UserProfileResSchema = UserSchema.pick({ email: true, id: true }).extend({
  role: z.string(),
  isDeviceTrustedInSession: z.boolean(),
  userProfile: UserProfileSchema.pick({
    firstName: true,
    lastName: true,
    avatar: true,
    username: true
  })
    .nullable()
    .optional()
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

export const RefreshTokenSuccessResSchema = z.object({
  message: z.string(),
  accessToken: z.string()
})

export const TrustDeviceBodySchema = z.object({}).strict()

export const RememberMeBodySchema = z
  .object({
    rememberMe: z.boolean()
  })
  .strict()

export type TrustDeviceBodyType = z.infer<typeof TrustDeviceBodySchema>
export type RememberMeBodyType = z.infer<typeof RememberMeBodySchema>

export type RefreshTokenSuccessResType = z.infer<typeof RefreshTokenSuccessResSchema>

export const UntrustDeviceBodySchema = z.object({}).strict()

export const LogoutFromDeviceBodySchema = z
  .object({
    deviceId: z.number().int().positive()
  })
  .strict()

export type UntrustDeviceBodyType = z.infer<typeof UntrustDeviceBodySchema>
export type LogoutFromDeviceBodyType = z.infer<typeof LogoutFromDeviceBodySchema>

export const ChangePasswordBodySchema = z.object({
  currentPassword: z.string().min(1, 'validation.password.required'),
  newPassword: z.string().min(8, 'validation.password.min.8').max(100, 'validation.string.max.100')
})
