import { z } from 'zod'
import { BasePaginationQuerySchema, createPaginatedResponseSchema } from 'src/shared/models/pagination.model'
import { AuditLogStatus } from './audit-log.service'

export const AuditLogSchema = z.object({
  id: z.number(),
  timestamp: z.date(),
  userId: z.number().nullable(),
  userEmail: z.string().email().nullable(),
  action: z.string(),
  entity: z.string().nullable(),
  entityId: z.string().nullable(),
  ipAddress: z.string().nullable(),
  userAgent: z.string().nullable(),
  status: z.nativeEnum(AuditLogStatus),
  errorMessage: z.string().nullable(),
  details: z.any().nullable(),
  notes: z.string().nullable()
})

export const AuditLogQuerySchema = BasePaginationQuerySchema.extend({
  sortBy: z.enum(['id', 'timestamp', 'action', 'entity', 'status', 'userEmail']).optional().default('timestamp'),
  userId: z.coerce.number().optional(),
  action: z.string().optional(),
  entity: z.string().optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  status: z.nativeEnum(AuditLogStatus).optional(),
  all: z.coerce.boolean().optional().default(false)
})

export const AuditLogResponseSchema = createPaginatedResponseSchema(AuditLogSchema)

export type AuditLogType = z.infer<typeof AuditLogSchema>
export type AuditLogQueryType = z.infer<typeof AuditLogQuerySchema>
export type AuditLogResponseType = z.infer<typeof AuditLogResponseSchema>
