import { createZodDto } from 'nestjs-zod'
import { BasePaginationQuerySchema } from 'src/shared/models/core.model'

// ==================== PAGINATION DTOs ====================

export class BasePaginationQueryDTO extends createZodDto(BasePaginationQuerySchema) {}
