import { UserStatus } from 'src/shared/constants/auth.constant'
import { PasswordErrorMessages } from 'src/routes/auth/error.model'
import { z } from 'zod'

const emailSchema = z
  .string()
  .email()
  .transform((email) => email.toLowerCase())
const passwordSchema = z
  .string()
  .min(8, PasswordErrorMessages.MIN_LENGTH)
  .max(100, PasswordErrorMessages.MAX_LENGTH)
  .regex(/[A-Z]/, PasswordErrorMessages.UPPERCASE)
  .regex(/[a-z]/, PasswordErrorMessages.LOWERCASE)
  .regex(/[0-9]/, PasswordErrorMessages.NUMBER)
  .regex(/[^A-Za-z0-9]/, PasswordErrorMessages.SPECIAL_CHAR)

export const UserSchema = z.object({
  id: z.number(),
  email: emailSchema,
  name: z.string().min(1).max(100),
  password: passwordSchema,
  phoneNumber: z.string().min(9).max(15),
  avatar: z.string().nullable(),
  totpSecret: z.string().nullable(),
  status: z.enum([UserStatus.ACTIVE, UserStatus.INACTIVE, UserStatus.BLOCKED]),
  roleId: z.number().positive(),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type UserType = z.infer<typeof UserSchema>
