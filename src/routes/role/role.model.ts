import { Role as PrismaRole, Permission } from '@prisma/client'

export class Role implements PrismaRole {
  id: number
  name: string
  description: string | null
  isSystemRole: boolean
  isSuperAdmin: boolean
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null
  createdById: number | null
  updatedById: number | null
  deletedById: number | null
  permissions?: Permission[]
}

// You can also re-export related types or enums if necessary, for example:
// export { SomeEnumRelatedToRole } from '@prisma/client'
