import { z } from 'zod'

/**
 * Role Schema
 */
export const RoleSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  description: z.string().optional(),
  isActive: z.boolean().default(true)
})

export type RoleType = z.infer<typeof RoleSchema>
