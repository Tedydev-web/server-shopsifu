import { PermissionSchema } from 'src/shared/models/shared-permission.model'
import { BasePaginationQuerySchema, PaginationMetadataSchema } from 'src/shared/models/pagination.model'
import { z } from 'zod'

// --- Schemas for paginated list ---
export const GetPermissionsResSchema = z.object({
  data: z.array(PermissionSchema),
  metadata: PaginationMetadataSchema,
})

export const GetPermissionsQuerySchema = BasePaginationQuerySchema.extend({
  module: z.string().optional(),
  sortBy: z.enum(['name', 'path', 'module', 'createdAt']).optional(),
})

// --- Schemas for grouped list ---
export const PermissionGroupSchema = z.object({
  module: z.string(),
  permissions: z.array(PermissionSchema),
})

export const GetGroupedPermissionsResSchema = z.array(PermissionGroupSchema)

// --- Common Schemas ---
export const GetPermissionParamsSchema = z
  .object({
    permissionId: z.coerce.number().int().positive(),
  })
  .strict()

export const GetPermissionDetailResSchema = PermissionSchema

export const CreatePermissionBodySchema = PermissionSchema.pick({
  name: true,
  path: true,
  method: true,
  module: true,
  description: true,
}).strict()

export const UpdatePermissionBodySchema = CreatePermissionBodySchema.partial()

export type PermissionType = z.infer<typeof PermissionSchema>
export type GetPermissionsResType = z.infer<typeof GetPermissionsResSchema>
export type GetPermissionsQueryType = z.infer<typeof GetPermissionsQuerySchema>
export type PermissionGroupType = z.infer<typeof PermissionGroupSchema>
export type GetGroupedPermissionsResType = z.infer<typeof GetGroupedPermissionsResSchema>
export type GetPermissionDetailResType = z.infer<typeof GetPermissionDetailResSchema>
export type CreatePermissionBodyType = z.infer<typeof CreatePermissionBodySchema>
export type GetPermissionParamsType = z.infer<typeof GetPermissionParamsSchema>
export type UpdatePermissionBodyType = z.infer<typeof UpdatePermissionBodySchema>
