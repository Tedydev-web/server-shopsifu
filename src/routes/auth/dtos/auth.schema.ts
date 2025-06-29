import { TypeOfVerificationCode } from 'src/shared/constants/auth.constant'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { z } from 'zod'

export const RegisterBodySchema = UserSchema.pick({
  email: true,
  password: true,
  name: true,
  phoneNumber: true,
})
  .extend({
    confirmPassword: z.string().min(6).max(100),
    code: z.string().length(6),
  })
  .strict()
  .superRefine(({ confirmPassword, password }, ctx) => {
    if (confirmPassword !== password) {
      ctx.addIssue({
        code: 'custom',
        message: 'Password and confirm password must match',
        path: ['confirmPassword'],
      })
    }
  })

export const VerificationCodeSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  code: z.string().length(6),
  type: z.enum([
    TypeOfVerificationCode.REGISTER,
    TypeOfVerificationCode.FORGOT_PASSWORD,
    TypeOfVerificationCode.LOGIN,
    TypeOfVerificationCode.DISABLE_2FA,
  ]),
  expiresAt: z.date(),
  createdAt: z.date(),
})

export const SendOTPBodySchema = VerificationCodeSchema.pick({
  email: true,
  type: true,
}).strict()

export const LoginBodySchema = UserSchema.pick({
  email: true,
  password: true,
})
  .extend({
    totpCode: z.string().length(6).optional(), // 2FA code
    code: z.string().length(6).optional(), // Email OTP code
    rememberMe: z.boolean().optional().default(false),
  })
  .strict()
  .superRefine(({ totpCode, code }, ctx) => {
    // Nếu mà truyền cùng lúc totpCode và code thì sẽ add issue
    const message = 'Bạn chỉ nên truyền mã xác thực 2FA hoặc mã OTP. Không được truyền cả 2'
    if (totpCode !== undefined && code !== undefined) {
      ctx.addIssue({
        path: ['totpCode'],
        message,
        code: 'custom',
      })
      ctx.addIssue({
        path: ['code'],
        message,
        code: 'custom',
      })
    }
  })

export const RefreshTokenBodySchema = z
  .object({
    // refreshToken sẽ được đọc từ cookie, body này sẽ trống
  })
  .strict()

export const RefreshTokenSchema = z.object({
  token: z.string(),
  userId: z.number(),
  deviceId: z.number(),
  expiresAt: z.date(),
  createdAt: z.date(),
})

export const RoleSchema = z.object({
  id: z.number(),
  name: z.string(),
  description: z.string(),
  isActive: z.boolean(),
  createdAt: z.date(),
  updatedAt: z.date(),
  deletedAt: z.date().nullable(),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedById: z.number().nullable(),
})

export const LogoutBodySchema = z.object({
  // refreshToken sẽ được đọc từ cookie, body này sẽ trống
})

export const GoogleAuthStateSchema = z.object({
  userAgent: z.string(),
  ip: z.string(),
})

export const GetAuthorizationUrlResSchema = z.object({
  url: z.string().url(),
})

export const ForgotPasswordBodySchema = z
  .object({
    email: z.string().email(),
    code: z.string().length(6),
    newPassword: z.string().min(6).max(100),
    confirmNewPassword: z.string().min(6).max(100),
  })
  .strict()
  .superRefine(({ confirmNewPassword, newPassword }, ctx) => {
    if (confirmNewPassword !== newPassword) {
      ctx.addIssue({
        code: 'custom',
        message: 'Mật khẩu và mật khẩu xác nhận phải giống nhau',
        path: ['confirmNewPassword'],
      })
    }
  })

export const DisableTwoFactorBodySchema = z
  .object({
    totpCode: z.string().length(6).optional(),
    code: z.string().length(6).optional(),
  })
  .strict()
  .superRefine(({ totpCode, code }, ctx) => {
    const message = 'Bạn phải cung cấp mã xác thực 2FA hoặc mã OTP. Không được cung cấp cả 2'
    // Nếu cả 2 đều có hoặc không có thì sẽ nhảy vào if
    if ((totpCode !== undefined) === (code !== undefined)) {
      ctx.addIssue({
        path: ['totpCode'],
        message,
        code: 'custom',
      })
      ctx.addIssue({
        path: ['code'],
        message,
        code: 'custom',
      })
    }
  })

export const TwoFactorSetupResSchema = z.object({
  secret: z.string(),
  uri: z.string(),
})
