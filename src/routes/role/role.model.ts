import { z } from 'zod'
import { RoleSchema } from 'src/shared/models/shared-role.model'
import { PermissionSchema } from 'src/shared/models/shared-permission.model'

export const RoleWithPermissionsSchema = RoleSchema.extend({
  permissions: z.array(PermissionSchema)
})

export const GetRolesResSchema = z.object({
  message: z.string().optional(),
  data: z.array(RoleSchema),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number(),
    hasNext: z.boolean(),
    hasPrev: z.boolean()
  })
})

export const GetRolesQuerySchema = z
  .object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().positive().default(10),
    name: z.string().optional()
  })
  .strict()

export const GetRoleParamsSchema = z
  .object({
    roleId: z.string()
  })
  .strict()

export const GetRoleDetailResSchema = z.object({
  message: z.string().optional(),
  data: RoleWithPermissionsSchema
})

export const CreateRoleBodySchema = RoleSchema.pick({
  name: true,
  description: true,
  isActive: true
}).strict()

export const CreateRoleResSchema = z.object({
  message: z.string().optional(),
  data: RoleSchema
})

export const UpdateRoleBodySchema = RoleSchema.pick({
  name: true,
  description: true,
  isActive: true
})
  .extend({
    permissionIds: z.array(z.string())
  })
  .strict()

export type RoleWithPermissionsType = z.infer<typeof RoleWithPermissionsSchema>
export type GetRolesResType = z.infer<typeof GetRolesResSchema>
export type GetRolesQueryType = z.infer<typeof GetRolesQuerySchema>
export type GetRoleDetailResType = z.infer<typeof GetRoleDetailResSchema>
export type CreateRoleResType = z.infer<typeof CreateRoleResSchema>
export type CreateRoleBodyType = z.infer<typeof CreateRoleBodySchema>
export type GetRoleParamsType = z.infer<typeof GetRoleParamsSchema>
export type UpdateRoleBodyType = z.infer<typeof UpdateRoleBodySchema>
