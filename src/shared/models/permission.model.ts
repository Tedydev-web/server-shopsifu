import { z } from 'zod'
import { HTTPMethod as PrismaHTTPMethod } from '@prisma/client'

export const PermissionSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  description: z.string().default(''),
  path: z.string(),
  method: z.nativeEnum(PrismaHTTPMethod),
  createdById: z.number().int().nullable().optional(),
  updatedById: z.number().int().nullable().optional(),
  deletedById: z.number().int().nullable().optional(),
  deletedAt: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type PermissionType = z.infer<typeof PermissionSchema>
