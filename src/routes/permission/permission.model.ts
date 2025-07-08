import { PermissionSchema } from 'src/shared/models/shared-permission.model'
import { z } from 'zod'
import { PaginationResponseSchema } from 'src/shared/models/pagination.model'
import { PaginationQuerySchema } from 'src/shared/models/request.model'

export const GetPermissionsResSchema = PaginationResponseSchema(PermissionSchema)

export const GetPermissionsQuerySchema = PaginationQuerySchema.pick({
  page: true,
  limit: true,
  search: true
}).extend({
  sortBy: z.enum(['path', 'method', 'module', 'createdAt', 'updatedAt']).default('createdAt'),
  orderBy: z.enum(['asc', 'desc']).default('desc')
})

export const GetPermissionParamsSchema = z
  .object({
    permissionId: z.coerce.number() // Phải thêm coerce để chuyển từ string sang number
  })
  .strict()

export const GetPermissionDetailResSchema = PermissionSchema

export const CreatePermissionBodySchema = PermissionSchema.pick({
  name: true,
  path: true,
  method: true,
  module: true
}).strict()

export const UpdatePermissionBodySchema = CreatePermissionBodySchema

export type PermissionType = z.infer<typeof PermissionSchema>
export type GetPermissionsResType = z.infer<typeof GetPermissionsResSchema>
export type GetPermissionsQueryType = z.infer<typeof GetPermissionsQuerySchema>
export type GetPermissionDetailResType = z.infer<typeof GetPermissionDetailResSchema>
export type CreatePermissionBodyType = z.infer<typeof CreatePermissionBodySchema>
export type GetPermissionParamsType = z.infer<typeof GetPermissionParamsSchema>
export type UpdatePermissionBodyType = z.infer<typeof UpdatePermissionBodySchema>
