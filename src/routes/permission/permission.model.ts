import { PermissionSchema } from 'src/shared/models/shared-permission.model'
import { z } from 'zod'
import { BasePaginationQuerySchema, PaginationMetadataSchema } from 'src/shared/models/pagination.model'

export const GetPermissionsResSchema = z.object({
  data: z.array(PermissionSchema),
  metadata: PaginationMetadataSchema,
})

export const GetPermissionsQuerySchema = BasePaginationQuerySchema

export const GetPermissionParamsSchema = z
  .object({
    permissionId: z.coerce.number(), // Phải thêm coerce để chuyển từ string sang number
  })
  .strict()

export const GetPermissionDetailResSchema = PermissionSchema

export const CreatePermissionBodySchema = PermissionSchema.pick({
  name: true,
  path: true,
  method: true,
  module: true,
}).strict()

export const UpdatePermissionBodySchema = CreatePermissionBodySchema

export type PermissionType = z.infer<typeof PermissionSchema>
export type GetPermissionsResType = z.infer<typeof GetPermissionsResSchema>
export type GetPermissionsQueryType = z.infer<typeof GetPermissionsQuerySchema>
export type GetPermissionDetailResType = z.infer<typeof GetPermissionDetailResSchema>
export type CreatePermissionBodyType = z.infer<typeof CreatePermissionBodySchema>
export type GetPermissionParamsType = z.infer<typeof GetPermissionParamsSchema>
export type UpdatePermissionBodyType = z.infer<typeof UpdatePermissionBodySchema>
