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

export const ChangePasswordSchema = z
  .object({
    currentPassword: z.string({
      required_error: validationMessages.required('Mật khẩu hiện tại')
    }),
    newPassword: passwordSchema,
    confirmPassword: passwordSchema,
    revokeOtherSessions: z.boolean().default(true)
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Mật khẩu xác nhận không khớp.',
    path: ['confirmPassword']
  })
  .refine((data) => data.newPassword !== data.currentPassword, {
    message: 'Mật khẩu mới phải khác với mật khẩu hiện tại.',
    path: ['newPassword']
  })

export class InitiatePasswordResetDto extends createZodDto(InitiatePasswordResetSchema) {}
export class SetNewPasswordDto extends createZodDto(SetNewPasswordSchema) {}
export class ChangePasswordDto extends createZodDto(ChangePasswordSchema) {}
