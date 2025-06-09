import { Role as PrismaRole, Permission } from '@prisma/client'

export type Role = PrismaRole & {
  permissions?: Permission[] // Optional: if you frequently include permissions with roles
}

// You can also re-export related types or enums if necessary, for example:
// export { SomeEnumRelatedToRole } from '@prisma/client'
