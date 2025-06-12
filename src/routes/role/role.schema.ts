import { z } from 'zod'

export const RoleSchema = z.object({
  name: z.string().min(1, { message: 'Name is required' }).max(100),
  description: z.string().max(500).optional().nullable(),
  isSystemRole: z.boolean().optional(),
  isSuperAdmin: z.boolean().optional(),
  permissionIds: z.array(z.number().int().positive()).optional()
})
