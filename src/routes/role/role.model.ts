import { z } from 'zod'
import { RoleSchema } from 'src/shared/models/shared-role.model'
import { PermissionSchema } from 'src/shared/models/shared-permission.model'
import { PaginationResponseSchema } from 'src/shared/models/pagination.model'
import { PaginationQuerySchema } from 'src/shared/models/request.model'

export const RoleWithPermissionsSchema = RoleSchema.extend({
	permissions: z.array(PermissionSchema)
})

export const GetRolesResSchema = PaginationResponseSchema(RoleSchema)

export const GetRolesQuerySchema = PaginationQuerySchema.pick({
	page: true,
	limit: true,
	search: true
}).extend({
	sortBy: z.enum(['name', 'createdAt', 'updatedAt']).default('createdAt'),
	orderBy: z.enum(['asc', 'desc']).default('desc')
})

export const GetRoleParamsSchema = z
	.object({
		roleId: z.coerce.number()
	})
	.strict()

export const GetRoleDetailResSchema = RoleWithPermissionsSchema

export const CreateRoleBodySchema = RoleSchema.pick({
	name: true,
	description: true,
	isActive: true
}).strict()

export const CreateRoleResSchema = RoleSchema

export const UpdateRoleBodySchema = RoleSchema.pick({
	name: true,
	description: true,
	isActive: true
})
	.extend({
		permissionIds: z.array(z.number())
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
