import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

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

export const InitiatePasswordResetSchema = z.object({
  email: z
    .string({
      required_error: validationMessages.required('Email')
    })
    .email(validationMessages.email('Email'))
})

export const SetNewPasswordSchema = z
  .object({
    newPassword: passwordSchema,
    confirmPassword: passwordSchema,
    revokeAllSessions: z.boolean().optional().default(false)
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Mật khẩu xác nhận không khớp.',
    path: ['confirmPassword']
  })

export const ChangePasswordSchema = z.object({
  currentPassword: z.string(),
  newPassword: z.string().min(8, 'Password must be at least 8 characters long'),
  revokeOtherSessions: z.boolean().default(true)
})

export class InitiatePasswordResetDto extends createZodDto(InitiatePasswordResetSchema) {}
export class SetNewPasswordDto extends createZodDto(SetNewPasswordSchema) {}
export class ChangePasswordDto extends createZodDto(ChangePasswordSchema) {}
