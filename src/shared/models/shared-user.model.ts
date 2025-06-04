import { z } from 'zod'
import { TwoFactorMethodType } from '../constants/auth.constants'
import { UserStatus as PrismaUserStatus } from '@prisma/client'
import { UserProfileSchema } from './user-profile.model'
import { RoleSchema } from 'src/shared/models/role.model'
import { DeviceSchema } from './device.model'

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
