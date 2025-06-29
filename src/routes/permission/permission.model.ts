import {
  createTypedSuccessResponseSchema,
  createTypedPaginatedResponseSchema,
  MessageResSchema,
} from 'src/shared/models/response.model'
import { PermissionSchema } from 'src/shared/models/shared-permission.model'
import { BasePaginationQuerySchema, PaginatedResponseType } from 'src/shared/models/pagination.model'
import { z } from 'zod'

// Response Schemas
export const GetPermissionsResSchema = createTypedPaginatedResponseSchema(PermissionSchema)
export const GetPermissionDetailResSchema = createTypedSuccessResponseSchema(PermissionSchema)
export const CreatePermissionResSchema = createTypedSuccessResponseSchema(PermissionSchema)
export const UpdatePermissionResSchema = createTypedSuccessResponseSchema(PermissionSchema)
export const DeletePermissionResSchema = MessageResSchema

// Request Schemas
export const GetPermissionParamsSchema = z
  .object({
    permissionId: z.coerce.number(),
  })
  .strict()

export const CreatePermissionBodySchema = PermissionSchema.pick({
  name: true,
  path: true,
  method: true,
  module: true,
}).strict()

export const UpdatePermissionBodySchema = CreatePermissionBodySchema

// Pagination Schema (re-export for module-specific customization if needed)
export const PermissionPaginationQuerySchema = BasePaginationQuerySchema

// Types
export type PermissionType = z.infer<typeof PermissionSchema>
export type GetPermissionsResType = z.infer<typeof GetPermissionsResSchema>
export type GetPermissionDetailResType = z.infer<typeof GetPermissionDetailResSchema>
export type CreatePermissionResType = z.infer<typeof CreatePermissionResSchema>
export type UpdatePermissionResType = z.infer<typeof UpdatePermissionResSchema>
export type DeletePermissionResType = z.infer<typeof DeletePermissionResSchema>
export type GetPermissionParamsType = z.infer<typeof GetPermissionParamsSchema>
export type CreatePermissionBodyType = z.infer<typeof CreatePermissionBodySchema>
export type UpdatePermissionBodyType = z.infer<typeof UpdatePermissionBodySchema>

// Pagination Types (re-export for module use)
export type PermissionPaginationQueryType = z.infer<typeof PermissionPaginationQuerySchema>

// Re-export PaginatedResponseType for module use
export type { PaginatedResponseType }
