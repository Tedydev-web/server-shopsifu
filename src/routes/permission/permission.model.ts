import { Permission as PrismaPermission, Prisma } from '@prisma/client'

export class Permission implements PrismaPermission {
  id: number
  action: string
  subject: string
  description: string | null
  conditions: Prisma.JsonValue | null
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null
  uiMetadata: Prisma.JsonValue | null
  isSystemPermission: boolean
  createdById: number | null
  updatedById: number | null
  deletedById: number | null
}
