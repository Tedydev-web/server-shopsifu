import { UserStatus } from 'src/shared/constants/auth.constant'
import { z } from 'zod'

// Import error codes
import { VALIDATION_MESSAGES } from 'src/shared/models/error.model'

export const UserSchema = z.object({
  id: z.number(),
  email: z.string().email({ message: VALIDATION_MESSAGES.INVALID_EMAIL }),
  name: z.string().min(1, { message: 'ERROR.NAME_TOO_SHORT' }).max(100, { message: 'ERROR.NAME_TOO_LONG' }),
  password: z.string().min(6, { message: 'ERROR.PASSWORD_TOO_SHORT' }).max(100, { message: 'ERROR.PASSWORD_TOO_LONG' }),
  phoneNumber: z
    .string()
    .min(9, { message: 'ERROR.PHONE_NUMBER_TOO_SHORT' })
    .max(15, { message: 'ERROR.PHONE_NUMBER_TOO_LONG' }),
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
