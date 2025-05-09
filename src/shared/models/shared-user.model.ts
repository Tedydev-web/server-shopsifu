import { UserStatus } from 'src/shared/constants/auth.constant'
import { z } from 'zod'

export const UserSchema = z.object({
  id: z.number(),
  email: z.string({ message: 'Error.InvalidEmail' }).email({ message: 'Error.InvalidEmail' }),
  name: z.string({ message: 'Error.InvalidName' }).min(1, { message: 'Error.InvalidName' }).max(100, {
    message: 'Error.InvalidName'
  }),
  password: z.string({ message: 'Error.InvalidPassword' }).min(6, { message: 'Error.InvalidPassword' }).max(100, {
    message: 'Error.InvalidPassword'
  }),
  phoneNumber: z
    .string({ message: 'Error.InvalidPhoneNumber' })
    .min(9, { message: 'Error.InvalidPhoneNumber' })
    .max(15, {
      message: 'Error.InvalidPhoneNumber'
    }),
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
