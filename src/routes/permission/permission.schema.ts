import { z } from 'zod'

// ===================================================================================
//                                     SCHEMAS
// ===================================================================================

export const PermissionSchema = z.object({
  action: z
    .string()
    .min(1, 'Action must not be empty')
    .max(255, 'Action must be less than 255 characters')
    .regex(/^[a-zA-Z0-9_:]+$/, 'Action can only contain letters, numbers, underscores, and colons'),
  subject: z
    .string()
    .min(1, 'Subject must not be empty')
    .max(255, 'Subject must be less than 255 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Subject can only contain letters, numbers, and underscores'),
  description: z.string().max(500, 'Description must be less than 500 characters').optional().nullable(),
  conditions: z.record(z.any()).optional().nullable()
})

// --- Schemas for Individual Permission Item (Optimized) ---
export const PermissionItemSchema = z.object({
  id: z.number(),
  action: z.string(),
  httpMethod: z.string(), // GET, POST, PATCH, DELETE, etc.
  endpoint: z.string() // API endpoint path
})

// --- Schemas for Permission Group (by subject) (Optimized) ---
export const PermissionGroupSchema = z.object({
  subject: z.string(),
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
