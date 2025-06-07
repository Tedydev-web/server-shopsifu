import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { TwoFactorMethodType } from '../auth/shared/constants/auth.constants'

const validationMessages = {
  required: (field: string) => `${field} không được để trống.`,
  minLength: (field: string, length: number) => `${field} phải có ít nhất ${length} ký tự.`,
  email: (field: 'Email' | 'Tài khoản') => `${field} không hợp lệ.`
}

const passwordSchema = z
  .string({
    required_error: validationMessages.required('Mật khẩu')
  })
  .min(8, validationMessages.minLength('Mật khẩu', 8))

// ===================================================================================
// Schemas for Response Data
// ===================================================================================

const UserProfileSchema = z.object({
  firstName: z.string().nullable(),
  lastName: z.string().nullable(),
  username: z.string().nullable(),
  phoneNumber: z.string().nullable(),
  avatar: z.string().nullable()
})

export const ProfileResponseSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  role: z.string(),
  status: z.string(),
  twoFactorEnabled: z.boolean(),
  googleId: z.string().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
  userProfile: UserProfileSchema.nullable()
})

export const ChangePasswordSchema = z
  .object({
    currentPassword: z.string({ required_error: validationMessages.required('Mật khẩu hiện tại') }),
    newPassword: passwordSchema,
    confirmPassword: passwordSchema,
    revokeOtherSessions: z.boolean().optional().default(false),
    twoFactorCode: z.string().optional(),
    twoFactorMethod: z.nativeEnum(TwoFactorMethodType).optional()
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Mật khẩu xác nhận không khớp.',
    path: ['confirmPassword']
  })

// ===================================================================================
// DTOs
// ===================================================================================

export class ProfileResponseDto extends createZodDto(ProfileResponseSchema) {}
export class ChangePasswordDto extends createZodDto(ChangePasswordSchema) {}
