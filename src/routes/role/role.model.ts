import { z } from 'zod'
import { BasePaginationQuerySchema, createPaginatedResponseSchema } from 'src/shared/models/pagination.model'
import { PermissionSchema } from 'src/routes/permission/permission.model'

export const RoleSchema = z.object({
  id: z.number().int().positive(),
  name: z.string().min(1).max(500),
  description: z.string().max(1000).optional().default(''),
  isActive: z.boolean().default(true),
  permissions: z.array(PermissionSchema).optional(), // Optional for response, not for create/update directly
  createdById: z.number().int().positive().nullable(),
  updatedById: z.number().int().positive().nullable(),
  deletedById: z.number().int().positive().nullable().optional(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export const GetRolesQuerySchema = BasePaginationQuerySchema.extend({
  sortBy: z.enum(['id', 'name', 'isActive', 'createdAt', 'updatedAt']).optional().default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  includeDeleted: z.coerce.boolean().optional().default(false),
  isActive: z.coerce.boolean().optional(),
  permissionIds: z
    .string()
    .optional()
    .transform((val) => val?.split(',').map(Number).filter(Boolean) ?? undefined),
  all: z.coerce.boolean().optional().default(false)
}).strict()

export const GetRolesResSchema = createPaginatedResponseSchema(RoleSchema)

export const GetRoleParamsSchema = z
  .object({
    roleId: z.coerce.number().int().positive()
  })
  .strict()

export const GetRoleDetailResSchema = RoleSchema

export const CreateRoleBodySchema = RoleSchema.pick({
  name: true,
  description: true,
  isActive: true
})
  .extend({
    permissionIds: z.array(z.number().int().positive()).optional().default([])
  })
  .strict()

export const UpdateRoleBodySchema = RoleSchema.pick({
  name: true,
  description: true,
  isActive: true
})
  .extend({
    permissionIds: z.array(z.number().int().positive()).optional()
  })
  .strict()

export const RestoreRoleBodySchema = z.object({}).strict()

export const AssignPermissionsToRoleBodySchema = z
  .object({
    permissionIds: z.array(z.number().int().positive()).min(1)
  })
  .strict()

export type RoleType = z.infer<typeof RoleSchema>
export type GetRolesQueryType = z.infer<typeof GetRolesQuerySchema>
export type GetRolesResType = z.infer<typeof GetRolesResSchema>
export type GetRoleParamsType = z.infer<typeof GetRoleParamsSchema>
export type GetRoleDetailResType = z.infer<typeof GetRoleDetailResSchema>
export type CreateRoleBodyType = z.infer<typeof CreateRoleBodySchema>
export type UpdateRoleBodyType = z.infer<typeof UpdateRoleBodySchema>
export type RestoreRoleBodyType = z.infer<typeof RestoreRoleBodySchema>
export type AssignPermissionsToRoleBodyType = z.infer<typeof AssignPermissionsToRoleBodySchema>
