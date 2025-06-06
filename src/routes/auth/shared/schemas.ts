import { z } from 'zod'
import { HTTPMethod as PrismaHTTPMethod, UserStatus as PrismaUserStatus } from '@prisma/client'
import { TwoFactorMethodType } from './constants/auth.constants'
import { UserProfileSchema, PickedUserProfileResponseSchema } from 'src/shared/dtos/user.dto'

export const PermissionSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  description: z.string().default(''),
  path: z.string(),
  method: z.nativeEnum(PrismaHTTPMethod),
  createdById: z.number().int().nullable().optional(),
  updatedById: z.number().int().nullable().optional(),
  deletedById: z.number().int().nullable().optional(),
  deletedAt: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type PermissionType = z.infer<typeof PermissionSchema>

export const DeviceSchema = z.object({
  id: z.number().int(),
  userId: z.number().int(),
  name: z.string().nullable().optional(),
  fingerprint: z.string().nullable().optional(),
  userAgent: z.string(),
  ip: z.string(),
  lastActive: z.date(),
  createdAt: z.date(),
  isActive: z.boolean().default(true),
  isTrusted: z.boolean().default(false),
  trustExpiration: z.date().nullable().optional(),
  lastKnownIp: z.string().nullable().optional(),
  lastKnownCountry: z.string().nullable().optional(),
  lastKnownCity: z.string().nullable().optional(),
  lastNotificationSentAt: z.date().nullable().optional()
})

export type DeviceType = z.infer<typeof DeviceSchema>

/**
 * Role Schema
 */
export const RoleSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  description: z.string().default('').optional(),
  isActive: z.boolean().default(true),
  permissions: z.array(z.lazy(() => PermissionSchema)).optional(),
  users: z.array(z.lazy(() => UserSchema)).optional(),
  createdById: z.number().int().nullable().optional(),
  updatedById: z.number().int().nullable().optional(),
  deletedById: z.number().int().nullable().optional(),
  deletedAt: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
})

/**
 * User Schema
 */
export const UserSchema = z.object({
  id: z.number().int(),
  email: z.string().email('Invalid email format'),
  password: z.string(),
  googleId: z.string().nullable().optional(),
  status: z.nativeEnum(PrismaUserStatus),
  roleId: z.number().int(),
  role: z.lazy(() => RoleSchema).optional(),
  devices: z.array(z.lazy(() => DeviceSchema)).optional(),
  twoFactorEnabled: z.boolean().nullable().optional(),
  twoFactorSecret: z.string().nullable().optional(),
  twoFactorMethod: z.nativeEnum(TwoFactorMethodType).nullable().optional(),
  twoFactorVerifiedAt: z.date().nullable().optional(),
  userProfile: z
    .lazy(() => UserProfileSchema)
    .nullable()
    .optional(),
  passwordChangedAt: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date(),
  deletedAt: z.date().nullable().optional(),
  isEmailVerified: z.boolean().default(true),
  pendingEmail: z.string().email('Invalid email format').nullable().optional(),
  emailVerificationToken: z.string().nullable().optional(),
  emailVerificationTokenExpiresAt: z.date().nullable().optional(),
  emailVerificationSentAt: z.date().nullable().optional(),
  createdById: z.number().int().nullable().optional(),
  updatedById: z.number().int().nullable().optional(),
  deletedById: z.number().int().nullable().optional()
})

export type UserType = z.infer<typeof UserSchema>
export type RoleType = z.infer<typeof RoleSchema>

/**
 * Common Schema
 */
export const MessageResponseSchema = z.object({
  message: z.string()
})

export type MessageResponseType = z.infer<typeof MessageResponseSchema>

/**
 * Authentication Schemas
 */
export const RegisterBodySchema = z
  .object({
    email: z.string().email({ message: 'Email không hợp lệ' }),
    password: z.string().min(8, { message: 'Mật khẩu phải có ít nhất 8 ký tự' }),
    confirmPassword: z.string().min(8, { message: 'Mật khẩu phải có ít nhất 8 ký tự' }),
    firstName: z.string().min(1, { message: 'Tên không được để trống' }),
    lastName: z.string().min(1, { message: 'Họ không được để trống' }),
    username: z.string().optional(),
    phoneNumber: z.string().optional()
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Mật khẩu không khớp',
    path: ['confirmPassword']
  })

export type RegisterBodyType = z.infer<typeof RegisterBodySchema>

/**
 * CompleteRegistration không yêu cầu email vì sẽ được lấy từ SLT context
 */
export const CompleteRegistrationSchema = z
  .object({
    password: z.string().min(8),
    confirmPassword: z.string().min(8),
    firstName: z.string().min(1),
    lastName: z.string().min(1),
    username: z.string().optional(),
    phoneNumber: z.string().optional()
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword']
  })

export const LoginBodySchema = z.object({
  emailOrUsername: z.string().min(1, { message: 'Email hoặc username không được để trống' }),
  password: z.string().min(1, { message: 'Mật khẩu không được để trống' }),
  rememberMe: z.boolean().optional().default(false)
})

export type LoginBodyType = z.infer<typeof LoginBodySchema>

export const UserAuthResponseSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  role: z.string(),
  isDeviceTrustedInSession: z.boolean(),
  userProfile: PickedUserProfileResponseSchema.nullable()
})

/**
 * OTP Related Schemas
 */
export const OtpVerificationSchema = z.object({
  code: z
    .string()
    .min(6, { message: 'Mã OTP phải có ít nhất 6 ký tự' })
    .max(6, { message: 'Mật khẩu và xác nhận mật khẩu không khớp' }),
  rememberMe: z.boolean().optional().default(false)
})

/**
 * 2FA Related Schemas
 */
export const TwoFactorVerifyBodySchema = z.object({
  code: z.string().min(6, { message: 'Mã xác thực phải có ít nhất 6 ký tự' }),
  rememberMe: z.boolean().optional().default(false)
})

export type TwoFactorVerifyBodyType = z.infer<typeof TwoFactorVerifyBodySchema>

export const DisableTwoFactorBodySchema = z.object({
  code: z.string().min(6, { message: 'Mã xác thực phải có ít nhất 6 ký tự' }),
  method: z.enum(['TOTP', 'RECOVERY_CODE', 'PASSWORD']).optional()
})

export type DisableTwoFactorBodyType = z.infer<typeof DisableTwoFactorBodySchema>

/**
 * Reset Password Related Schemas
 */
export const ResetPasswordBodySchema = z
  .object({
    token: z.string(),
    newPassword: z.string().min(8, { message: 'Mật khẩu phải có ít nhất 8 ký tự' }),
    confirmPassword: z.string().min(8, { message: 'Mật khẩu phải có ít nhất 8 ký tự' })
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Mật khẩu không khớp',
    path: ['confirmPassword']
  })

export type ResetPasswordBodyType = z.infer<typeof ResetPasswordBodySchema>
