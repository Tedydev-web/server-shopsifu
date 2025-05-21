import { z } from 'zod'
import { BasePaginationQuerySchema, createPaginatedResponseSchema } from 'src/shared/models/pagination.model'
import { HTTPMethod as PrismaHTTPMethod } from '@prisma/client'
import { HTTPMethod } from 'src/shared/constants/role.constant'

export { HTTPMethod } from 'src/shared/constants/role.constant'
export type HTTPMethodType = keyof typeof HTTPMethod

export const PermissionSchema = z.object({
  id: z.number().int().positive(),
  name: z.string().min(1).max(500),
  description: z.string().default(''),
  path: z.string().min(1).max(1000),
  method: z.enum([
    HTTPMethod.GET,
    HTTPMethod.POST,
    HTTPMethod.PUT,
    HTTPMethod.DELETE,
    HTTPMethod.PATCH,
    HTTPMethod.OPTIONS,
    HTTPMethod.HEAD
  ]),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export const GetPermissionsResSchema = createPaginatedResponseSchema(PermissionSchema)

export const GetPermissionParamsSchema = z
  .object({
    permissionId: z.coerce.number().int().positive()
  })
  .strict()

export const GetPermissionsQuerySchema = BasePaginationQuerySchema.extend({
  sortBy: z.enum(['id', 'name', 'path', 'method', 'createdAt', 'updatedAt']).optional().default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  includeDeleted: z.coerce.boolean().optional().default(false),
  method: z.nativeEnum(PrismaHTTPMethod).optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  all: z.coerce.boolean().optional().default(false)
}).strict()

export const GetPermissionDetailResSchema = PermissionSchema

export const CreatePermissionBodySchema = z
  .object({
    name: z.string().min(1).max(500),
    description: z.string().optional().default(''),
    path: z.string().min(1).max(1000),
    method: z.nativeEnum(PrismaHTTPMethod)
  })
  .strict()

export const UpdatePermissionBodySchema = z
  .object({
    name: z.string().min(1).max(500).optional(),
    description: z.string().optional(),
    path: z.string().min(1).max(1000).optional(),
    method: z.nativeEnum(PrismaHTTPMethod).optional()
  })
  .strict()

export const RestorePermissionBodySchema = z.object({}).strict()

export type PermissionType = z.infer<typeof PermissionSchema>
export type GetPermissionsResType = z.infer<typeof GetPermissionsResSchema>
export type GetPermissionDetailResType = z.infer<typeof GetPermissionDetailResSchema>
export type CreatePermissionBodyType = z.infer<typeof CreatePermissionBodySchema>
export type GetPermissionParamsType = z.infer<typeof GetPermissionParamsSchema>
export type UpdatePermissionBodyType = z.infer<typeof UpdatePermissionBodySchema>
export type GetPermissionsQueryType = z.infer<typeof GetPermissionsQuerySchema>
export type RestorePermissionBodyType = z.infer<typeof RestorePermissionBodySchema>
