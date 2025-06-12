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
