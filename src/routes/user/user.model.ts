import { User as PrismaUser, UserStatus, TwoFactorMethodType } from '@prisma/client'

// By exporting a class, we can use it as a value at runtime (e.g., for CASL).
// The `implements` keyword ensures it matches the shape of the Prisma model
// for type-checking purposes.
export class User implements PrismaUser {
  id: number
  email: string
  password: string
  status: UserStatus
  roleId: number | null
  isEmailVerified: boolean
  pendingEmail: string | null
  emailVerificationToken: string | null
  emailVerificationTokenExpiresAt: Date | null
  emailVerificationSentAt: Date | null
  twoFactorEnabled: boolean
  twoFactorSecret: string | null
  twoFactorMethod: TwoFactorMethodType | null
  twoFactorVerifiedAt: Date | null
  googleId: string | null
  passwordChangedAt: Date | null
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null
  createdById: number | null
  updatedById: number | null
  deletedById: number | null
}
