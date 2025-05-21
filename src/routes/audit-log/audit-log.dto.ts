import { createZodDto } from 'nestjs-zod'
import { AuditLogQuerySchema, AuditLogResponseSchema } from './audit-log.model'

export class AuditLogQueryDTO extends createZodDto(AuditLogQuerySchema) {}

export class AuditLogResponseDTO extends createZodDto(AuditLogResponseSchema) {}
