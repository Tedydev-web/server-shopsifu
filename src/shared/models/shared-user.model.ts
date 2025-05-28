import { TwoFactorMethodType } from '../../routes/auth/constants/auth.constants'
import { UserStatus as PrismaUserStatus } from '@prisma/client'
import { z } from 'zod'
import { UserProfileSchema } from './user-profile.model'

export const UserSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  password: z.string().min(6).max(100),
  status: z.nativeEnum(PrismaUserStatus),
  twoFactorEnabled: z.boolean().nullable().optional(),
  twoFactorSecret: z.string().nullable().optional(),
  twoFactorMethod: z.nativeEnum(TwoFactorMethodType).nullable().optional(),
  twoFactorVerifiedAt: z.date().nullable().optional(),
  roleId: z.number().positive(),
  userProfile: UserProfileSchema.nullable().optional(),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type UserType = z.infer<typeof UserSchema>
