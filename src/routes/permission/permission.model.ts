import { Permission as PrismaPermission } from '@prisma/client'

export type Permission = PrismaPermission

// 'category' field in Prisma Permission model is likely a string.
// If it were a Prisma enum, it would be imported differently or defined in the schema as such.
