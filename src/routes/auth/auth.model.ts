import { z } from 'zod'
import { TypeOfVerificationCode, TwoFactorMethodType } from 'src/shared/constants/auth.constants'
import { RoleSchema } from 'src/shared/models/role.model'
import { PickedUserProfileResponseSchema } from 'src/shared/dtos/user.dto'

export { RoleSchema }

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

/**
 * CompleteRegistration không yêu cầu email vì sẽ được lấy từ SLT context
 */
export const CompleteRegistrationSchema = z
  .object({
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
export type CompleteRegistrationBodyType = z.infer<typeof CompleteRegistrationSchema>

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

export type UserAuthResponseType = z.infer<typeof UserAuthResponseSchema>

/**
 * OTP Related Schemas
 */
export const OtpVerificationSchema = z.object({
  code: z.string().min(6, { message: 'Mã OTP phải có ít nhất 6 ký tự' }).max(6, { message: 'Mã OTP tối đa 6 ký tự' }),
  rememberMe: z.boolean().optional().default(false)
})

export type OtpVerificationType = z.infer<typeof OtpVerificationSchema>

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
