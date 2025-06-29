import { z } from 'zod'
import { RoleSchema } from 'src/shared/models/shared-role.model'
import { PermissionSchema } from 'src/shared/models/shared-permission.model'
import {
  createTypedSuccessResponseSchema,
  createTypedPaginatedResponseSchema,
  MessageResSchema,
} from 'src/shared/models/response.model'
import { BasePaginationQuerySchema, PaginatedResponseType } from 'src/shared/models/pagination.model'

export const RoleWithPermissionsSchema = RoleSchema.extend({
  permissions: z.array(PermissionSchema),
})

// Response Schemas
export const GetRolesResSchema = createTypedPaginatedResponseSchema(RoleSchema)
export const GetRoleDetailResSchema = createTypedSuccessResponseSchema(RoleWithPermissionsSchema)
export const CreateRoleResSchema = createTypedSuccessResponseSchema(RoleSchema)
export const UpdateRoleResSchema = createTypedSuccessResponseSchema(RoleWithPermissionsSchema)
export const DeleteRoleResSchema = MessageResSchema

export const GetRoleParamsSchema = z
  .object({
    roleId: z.coerce.number(),
  })
  .strict()

export const CreateRoleBodySchema = RoleSchema.pick({
  name: true,
  description: true,
  isActive: true,
}).strict()

export const UpdateRoleBodySchema = RoleSchema.pick({
  name: true,
  description: true,
  isActive: true,
})
  .extend({
    permissionIds: z.array(z.number()),
  })
  .strict()

// Pagination Schema (re-export for module-specific customization if needed)
export const RolePaginationQuerySchema = BasePaginationQuerySchema

// Types
export type RoleType = z.infer<typeof RoleSchema>
export type RoleWithPermissionsType = z.infer<typeof RoleWithPermissionsSchema>
export type GetRolesResType = z.infer<typeof GetRolesResSchema>
export type GetRoleDetailResType = z.infer<typeof GetRoleDetailResSchema>
export type CreateRoleResType = z.infer<typeof CreateRoleResSchema>
export type CreateRoleBodyType = z.infer<typeof CreateRoleBodySchema>
export type GetRoleParamsType = z.infer<typeof GetRoleParamsSchema>
export type UpdateRoleBodyType = z.infer<typeof UpdateRoleBodySchema>
export type UpdateRoleResType = z.infer<typeof UpdateRoleResSchema>
export type DeleteRoleResType = z.infer<typeof DeleteRoleResSchema>

// Pagination Types (re-export for module use)
export type RolePaginationQueryType = z.infer<typeof RolePaginationQuerySchema>

// Re-export PaginatedResponseType for module use
export type { PaginatedResponseType }
