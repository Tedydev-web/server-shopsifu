import { TwoFactorMethodType } from '../../routes/auth/constants/auth.constants'
import { UserStatus as PrismaUserStatus } from '@prisma/client'
import { z } from 'zod'
import { UserProfileSchema } from './user-profile.model'
import { RoleSchema } from 'src/routes/auth/auth.model'

export const UserSchema = z.object({
  id: z.number().int(),
  email: z.string().email('Invalid email format'),
  password: z.string(),
  googleId: z.string().nullable().optional(),
  status: z.nativeEnum(PrismaUserStatus),
  roleId: z.number().int(),
  role: z.lazy(() => RoleSchema).optional(),
  devices: z.array(z.any()).optional(),
  twoFactorEnabled: z.boolean().nullable().optional(),
  twoFactorSecret: z.string().nullable().optional(),
  twoFactorMethod: z.nativeEnum(TwoFactorMethodType).nullable().optional(),
  twoFactorVerifiedAt: z.date().nullable().optional(),
  userProfile: UserProfileSchema.nullable().optional(),
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
