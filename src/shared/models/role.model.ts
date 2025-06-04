import { z } from 'zod'
import { UserSchema } from './shared-user.model'
import { PermissionSchema } from './permission.model'

/**
 * Role Schema
 */
export const RoleSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  description: z.string().default('').optional(),
  isActive: z.boolean().default(true),
  permissions: z.array(z.lazy(() => PermissionSchema)).optional(),
  users: z.array(z.lazy(() => UserSchema)).optional(),
  createdById: z.number().int().nullable().optional(),
  updatedById: z.number().int().nullable().optional(),
  deletedById: z.number().int().nullable().optional(),
  deletedAt: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type RoleType = z.infer<typeof RoleSchema>
