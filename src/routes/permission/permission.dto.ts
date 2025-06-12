import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { Permission } from '@prisma/client'

// ===================================================================================
//                                     SCHEMAS
// ===================================================================================

const PermissionSchema = z.object({
  action: z
    .string()
    .min(1, { message: 'Action is required' })
    .max(100, { message: 'Action must be 100 characters or less' }),
  subject: z
    .string()
    .min(1, { message: 'Subject is required' })
    .max(255, { message: 'Subject must be 255 characters or less' }),
  description: z.string().max(500).optional().nullable(),
  category: z.string().max(100).optional().nullable(),
  conditions: z.record(z.any()).optional().nullable()
})

// --- Schemas for Individual Permission Item (Optimized) ---
const PermissionItemSchema = z.object({
  id: z.number(),
  action: z.string(),
  httpMethod: z.string(), // GET, POST, PATCH, DELETE, etc.
  endpoint: z.string() // API endpoint path
})

// --- Schemas for Permission Group (by subject) (Optimized) ---
const PermissionGroupSchema = z.object({
  subject: z.string(),
  displayName: z.string(),
  permissionsCount: z.number(),
  permissions: z.array(PermissionItemSchema)
})

// --- Schemas for Get Permissions (Grouped Response) (Optimized) ---
export const GetGroupedPermissionsResponseSchema = z.object({
  groups: z.array(PermissionGroupSchema),
  meta: z.object({
    currentPage: z.number(),
    totalPages: z.number(),
    totalGroups: z.number()
  })
})

export const GetPermissionsQuerySchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().optional().default(10)
})

// ===================================================================================
//                                       DTOs
// ===================================================================================

// --- Request DTOs ---
export class GetPermissionsQueryDto extends createZodDto(GetPermissionsQuerySchema) {}
export class CreatePermissionDto extends createZodDto(PermissionSchema) {}
export class UpdatePermissionDto extends createZodDto(PermissionSchema.partial()) {}

// --- Response DTOs ---
export class GetGroupedPermissionsResponseDto extends createZodDto(GetGroupedPermissionsResponseSchema) {}

// Infer and export types from Zod schemas
export type PermissionGroup = z.infer<typeof PermissionGroupSchema>
export type PermissionItem = z.infer<typeof PermissionItemSchema>

export class PermissionDto implements Omit<Permission, 'createdById' | 'updatedById' | 'deletedById'> {
  id: number
  action: string
  subject: string
  description: string | null
  category: string | null
  conditions: Record<string, any> | null
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null

  constructor(partial: Partial<PermissionDto>) {
    Object.assign(this, partial)
  }

  static fromEntity(entity: Permission): PermissionDto {
    return new PermissionDto({
      id: entity.id,
      action: entity.action,
      subject: entity.subject,
      description: entity.description,
      category: entity.category,
      conditions: entity.conditions as Record<string, any> | null,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      deletedAt: entity.deletedAt
    })
  }
}
